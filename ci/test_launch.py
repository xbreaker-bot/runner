import datetime as dt
import contextlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import launch


class LauncherTests(unittest.TestCase):
    def test_public_diagnostics_preserve_http_status_without_sensitive_exception_text(self):
        cause = urllib.error.HTTPError("https://hidden.example.org/repo?token=secret-value", 403,
                                       "hidden server response", {}, None)
        error = launch.CIError("http_request_failed")
        error.__cause__ = cause
        public = io.StringIO()
        with contextlib.redirect_stdout(public):
            detail = launch.public_failure("resolve_control_ref", error)
            launch.public_failure("execute_pipeline", RuntimeError("hidden command and secret-value"))
            launch.public_failure("execute_pipeline", launch.CIError("secret-value"))
        self.assertEqual(detail, {"stage": "resolve_control_ref", "code": "http_request_failed", "http_status": 403})
        self.assertIn("stage=resolve_control_ref", public.getvalue())
        self.assertIn("http_status=403", public.getvalue())
        self.assertIn("code=unexpected_error", public.getvalue())
        for forbidden in ("hidden.example.org", "secret-value", "hidden server response", "hidden command"):
            self.assertNotIn(forbidden, public.getvalue())

    def test_configuration_failure_prints_reason_without_secret_values(self):
        env = {"GH_BOT_WORKFLOW_TOKEN": "hidden-token", "CI_SOURCE_REPOSITORY": "private/source",
               "CI_RUNNER_REPOSITORY": "private/executor", "GITHUB_REPOSITORY": "private/executor",
               "CI_ALLOWED_ACTORS": "[hidden-actor]", "GITHUB_ACTOR": "hidden-actor",
               "CI_CONTROL_REF": "trusted", "CI_S3_ENDPOINT": "https://private.example.org",
               "CI_S3_BUCKET": "private-bucket", "CI_S3_ACCESS_KEY_ID": "hidden-access",
               "CI_S3_SECRET_ACCESS_KEY": "hidden-secret", "CI_S3_GATE_TOKEN": "hidden-gate",
               "CI_S3_REGION": "us-east-1"}
        for key, value, reason in (("CI_ALLOWED_ACTORS", "[hidden-actor]", "invalid_actor_configuration"),
                                   ("GH_BOT_WORKFLOW_TOKEN", "", "missing_configuration:GH_BOT_WORKFLOW_TOKEN"),
                                   ("CI_SOURCE_REPOSITORY", "invalid", "invalid_repository_configuration:CI_SOURCE_REPOSITORY"),
                                   ("GITHUB_REPOSITORY", "other/executor", "runner_repository_not_allowed")):
            public = io.StringIO()
            with self.subTest(key=key), patch.dict(os.environ, {**env, key: value}, clear=True), \
                    contextlib.redirect_stdout(public), patch.object(launch, "github") as github:
                self.assertEqual(launch.main(), 1)
                github.assert_not_called()
                self.assertIn("[" + reason + "]", public.getvalue())
                for secret in ("hidden-token", "hidden-actor", "hidden-secret", "private/source", "private.example.org"):
                    self.assertNotIn(secret, public.getvalue())

    def test_config_requires_secrets_and_checks_caller_without_disclosing_values(self):
        env = {"GH_BOT_WORKFLOW_TOKEN": "test-token", "CI_SOURCE_REPOSITORY": "example/source",
               "CI_RUNNER_REPOSITORY": "example/executor", "GITHUB_REPOSITORY": "example/executor",
               "CI_ALLOWED_ACTORS": '["test-operator"]', "GITHUB_ACTOR": "test-operator",
               "CI_CONTROL_REF": "trusted", "CI_S3_ENDPOINT": "https://s3.example.org",
               "CI_S3_BUCKET": "test-bucket", "CI_S3_ACCESS_KEY_ID": "test-access",
               "CI_S3_SECRET_ACCESS_KEY": "test-secret", "CI_S3_GATE_TOKEN": "test-gate",
               "CI_S3_REGION": "us-east-1"}
        launch.validate_config(env)
        for key, value in (("CI_SOURCE_REPOSITORY", ""), ("CI_RUNNER_REPOSITORY", "other/executor"),
                           ("CI_ALLOWED_ACTORS", "not-json"), ("CI_ALLOWED_ACTORS", "[]"),
                           ("GITHUB_ACTOR", "stranger"), ("CI_S3_BUCKET", "../bucket"),
                           ("GH_BOT_WORKFLOW_TOKEN", "")):
            with self.subTest(key=key, value=value), self.assertRaises(launch.CIError) as raised:
                launch.validate_config({**env, key: value})
            self.assertNotIn("test-token", str(raised.exception))
            self.assertNotIn("example/source", str(raised.exception))

    def test_docker_cp_evidence_archive_accepts_root_directory(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as tar:
            for name in (".", "./empty", "./evidence"):
                item = tarfile.TarInfo(name)
                item.type = tarfile.DIRTYPE
                tar.addfile(item)
            item = tarfile.TarInfo("./evidence/result.txt")
            item.size = 4
            tar.addfile(item, io.BytesIO(b"pass"))
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "out"
            launch.extract(data.getvalue(), destination)
            self.assertEqual((destination / "evidence/result.txt").read_bytes(), b"pass")
            self.assertTrue((destination / "empty").is_dir())

    def test_root_entries_cannot_hide_files_or_links(self):
        for name, kind, strip_root in ((".", tarfile.REGTYPE, False),
                                      (".", tarfile.SYMTYPE, False),
                                      ("root", tarfile.SYMTYPE, True),
                                      ("root", tarfile.REGTYPE, True)):
            with self.subTest(name=name, kind=kind, strip_root=strip_root):
                data = io.BytesIO()
                with tarfile.open(fileobj=data, mode="w") as tar:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = "/etc/passwd"
                    tar.addfile(item, io.BytesIO())
                with tempfile.TemporaryDirectory() as tmp, self.assertRaises(launch.CIError):
                    launch.extract(data.getvalue(), Path(tmp) / "out", strip_root=strip_root)

    def test_orchestration_never_publishes_green_after_execution_or_upload_failure(self):
        for failure in (None, "pipeline_failed", "upload"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                event = root / "event.json"
                event.write_text(json.dumps({"inputs": {"source_sha": "a" * 40}}))
                env = {"GITHUB_ACTOR": "test-operator", "GITHUB_EVENT_NAME": "workflow_dispatch",
                       "GITHUB_EVENT_PATH": str(event), "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}
                env.update({k: "private" for k in ("GH_BOT_WORKFLOW_TOKEN",
                           "CI_S3_ENDPOINT", "CI_S3_ACCESS_KEY_ID", "CI_S3_SECRET_ACCESS_KEY", "CI_S3_GATE_TOKEN")})
                env.update({"CI_SOURCE_REPOSITORY": "test-owner/test-source", "CI_RUNNER_REPOSITORY": "test-owner/test-runner",
                            "GITHUB_REPOSITORY": "test-owner/test-runner", "CI_ALLOWED_ACTORS": '["test-operator"]',
                            "CI_CONTROL_REF": "main", "CI_S3_BUCKET": "test-bucket", "CI_S3_REGION": "us-east-1"})
                def snapshot(sha, token, destination):
                    ci = destination / ".ci/runner"
                    ci.mkdir(parents=True)
                    (ci / "manifest.json").write_text("{}")
                def execute(source, control, output, pipeline, log, manifest):
                    log.write(b"private execution output")
                    if failure == "pipeline_failed":
                        raise launch.CIError("pipeline_failed")
                public = io.StringIO()
                with patch.dict(os.environ, env), patch.object(launch.signal, "signal"), \
                     patch.object(launch, "github", return_value={"sha": "a" * 40}), \
                     patch.object(launch, "snapshot", side_effect=snapshot), \
                     patch.object(launch, "execute", side_effect=execute), \
                     patch.object(launch, "upload", side_effect=launch.CIError("failed") if failure == "upload" else None), \
                     patch.object(launch, "status") as status, contextlib.redirect_stdout(public):
                    rc = launch.main()
                expected = "success" if failure is None else "failure" if failure == "pipeline_failed" else "error"
                self.assertEqual(status.call_args.args[2], expected)
                self.assertEqual(rc, 0 if failure is None else 1)
                self.assertNotIn("private execution output", public.getvalue())
                self.assertNotIn("test-owner/test-source", public.getvalue())
                if failure == "pipeline_failed":
                    self.assertIn("stage=execute_pipeline code=pipeline_failed", public.getvalue())
                elif failure == "upload":
                    self.assertIn("stage=upload_evidence", public.getvalue())

    def test_dispatch_rejects_refs_commands_and_other_pipelines(self):
        for value in ("main", "a" * 39, "a" * 40 + ";id", "A" * 40, 42):
            with self.assertRaises(launch.CIError):
                launch.inputs("workflow_dispatch", {"inputs": {"source_sha": value}})
        for pipeline in ("bash", "s00;rm", "S00", "agent_memory", "agent-memory/../s00", "", None, 42):
            with self.subTest(pipeline=pipeline), self.assertRaises(launch.CIError):
                launch.inputs("workflow_dispatch",
                              {"inputs": {"source_sha": "a" * 40, "pipeline": pipeline}})
        self.assertEqual(launch.inputs("repository_dispatch", {
            "action": "private-source-ci", "client_payload": {"source_sha": "a" * 40}}), ("a" * 40, "s00"))

    def test_allowed_pipelines_are_dispatchable_and_match_the_workflow_choice(self):
        # Регламент S-24: pipeline `agent-memory` - постоянное имя серверного gate,
        # `s00` остаётся самостоятельной регрессией стенда.
        for pipeline in launch.ALLOWED_PIPELINES:
            with self.subTest(pipeline=pipeline):
                self.assertEqual(launch.inputs("workflow_dispatch", {"inputs": {
                    "source_sha": "a" * 40, "pipeline": pipeline}}), ("a" * 40, pipeline))
        # Choice workflow живёт в этой же копии launcher и обязан предлагать ровно
        # разрешённые значения: расхождение дало бы отказ после диспатча.
        workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "private-source-ci.yml"
        options = re.search(r"options:\s*\[([^\]]*)\]", workflow.read_text()).group(1)
        self.assertEqual(sorted(value.strip() for value in options.split(",")),
                         sorted(launch.ALLOWED_PIPELINES))

    def test_execute_requires_pinned_package_manager_and_pipeline_from_trusted_ci(self):
        digest = "sha256:" + "a" * 64
        base = {"version": 1,
                "images": {"node": "node:24.22.0-bookworm@" + digest,
                           "docker_cli": "docker:28.5.2-cli@" + digest,
                           "dind": "docker:28.5.2-dind@" + digest},
                "pipelines": {"agent-memory": {"script": "pipelines/agent-memory.sh",
                                               "timeout_seconds": 1200}}}
        with tempfile.TemporaryDirectory() as tmp:
            control = Path(tmp) / "ci"
            (control / "pipelines").mkdir(parents=True)
            (control / "pipelines" / "agent-memory.sh").write_text("#!/bin/sh\nexit 0\n")
            source = Path(tmp) / "source"
            source.mkdir()
            output = Path(tmp) / "out"
            output.mkdir()

            def run_with(manifest):
                (control / "manifest.json").write_text(json.dumps(manifest))
                calls = []

                def fake_run(args, log, **kwargs):
                    calls.append([str(item) for item in args])
                    if args[:2] == ["docker", "image"]:
                        return json.dumps(["node:24.22.0-bookworm@" + digest]).encode()
                    if args[:2] == ["docker", "build"]:
                        raise launch.CIError("stop_after_build")
                    return b""

                recorded = {}
                with patch.object(launch, "run", side_effect=fake_run):
                    with self.assertRaises(launch.CIError) as raised:
                        launch.execute(source, control, output, "agent-memory", io.BytesIO(), recorded)
                return calls, raised.exception, recorded

            # Pin package manager обязателен и обязан быть точной версией: worker
            # не должен скачивать pnpm во время прогона.
            for pin in (None, "latest", "12", "12.x", 12150, ""):
                manifest = dict(base)
                if pin is not None:
                    manifest["pnpm"] = pin
                with self.subTest(pin=pin), self.assertRaises(launch.CIError) as raised:
                    (control / "manifest.json").write_text(json.dumps(manifest))
                    launch.execute(source, control, output, "agent-memory", io.BytesIO(), {})
                self.assertEqual("invalid_package_manager_pin", str(raised.exception))

            calls, error, recorded = run_with({**base, "pnpm": "12.15.0"})
            self.assertEqual("stop_after_build", str(error))
            self.assertEqual(recorded["pnpm"], "12.15.0")
            build = next(call for call in calls if call[:2] == ["docker", "build"])
            self.assertIn("--build-arg", build)
            self.assertIn("PNPM_VERSION=12.15.0", build)

            # Pipeline, которого нет в доверенном manifest, - отказ по имени,
            # а не необработанная KeyError из чтения manifest.
            with self.assertRaises(launch.CIError) as raised:
                (control / "manifest.json").write_text(json.dumps({**base, "pnpm": "12.15.0",
                                                                  "pipelines": {"s00": {}}}))
                launch.execute(source, control, output, "agent-memory", io.BytesIO(), {})
            self.assertEqual("pipeline_not_allowed", str(raised.exception))

    def test_pipeline_timeout_bound_covers_the_measured_cold_server_gate_run(self):
        # Замер холодного прогона agent-memory на disposable DinD (2026-10-27):
        # 1074 с, из них 1034 с - скачка образа стенда внутри вложенного docker.
        # На пределе 1200 с запас был меньше 15%, поэтому launcher принимает до
        # 1800 с. Pipeline s00 остаётся на 1200 с: его прогон короче.
        digest = "sha256:" + "a" * 64
        manifest = {"version": 1, "pnpm": "12.15.0",
                    "images": {"node": "node:24.22.0-bookworm@" + digest,
                               "docker_cli": "docker:28.5.2-cli@" + digest,
                               "dind": "docker:28.5.2-dind@" + digest}}
        with tempfile.TemporaryDirectory() as tmp:
            control = Path(tmp) / "ci"
            (control / "pipelines").mkdir(parents=True)
            (control / "pipelines" / "agent-memory.sh").write_text("#!/bin/sh\nexit 0\n")
            source = Path(tmp) / "source"
            source.mkdir()
            output = Path(tmp) / "out"
            output.mkdir()

            def with_timeout(timeout):
                manifest["pipelines"] = {"agent-memory": {
                    "script": "pipelines/agent-memory.sh", "timeout_seconds": timeout}}
                (control / "manifest.json").write_text(json.dumps(manifest))

                def fake_run(args, log, **kwargs):
                    if args[:2] == ["docker", "image"]:
                        return json.dumps(["node:24.22.0-bookworm@" + digest]).encode()
                    if args[:2] == ["docker", "build"]:
                        raise launch.CIError("stop_after_build")
                    return b""

                with patch.object(launch, "run", side_effect=fake_run):
                    with self.assertRaises(launch.CIError) as raised:
                        launch.execute(source, control, output, "agent-memory", io.BytesIO(), {})
                return str(raised.exception)

            self.assertEqual("stop_after_build", with_timeout(1800))
            for timeout in (1801, 10 ** 6, 29, "600", None):
                with self.subTest(timeout=timeout):
                    self.assertEqual("invalid_pipeline_timeout", with_timeout(timeout))

    def test_archive_rejects_traversal_links_and_duplicate_files(self):
        for kind in ("traversal", "symlink", "hardlink", "duplicate"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                data = io.BytesIO()
                with tarfile.open(fileobj=data, mode="w") as tar:
                    item = tarfile.TarInfo("../outside" if kind == "traversal" else "file")
                    if kind in ("symlink", "hardlink"):
                        item.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                        item.linkname = "/etc/passwd"
                    tar.addfile(item, io.BytesIO())
                    if kind == "duplicate":
                        tar.addfile(item, io.BytesIO())
                with self.assertRaises(launch.CIError):
                    launch.extract(data.getvalue(), Path(tmp) / "out")

    def test_extract_normalizes_directory_modes_for_unprivileged_container_users(self):
        # Режимы файлов лаунчер выставлял всегда, каталоги - нет: они наследовали
        # umask 0o077 из main. docker build это не заметил бы (он root), а вот
        # COPY переносит режим каталога в образ, и роль postgres в стенде БД
        # перестаёт видеть sql/operator. Поэтому нормализация проверяется тестом.
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as tar:
            nested = tarfile.TarInfo("sql/operator")
            nested.type = tarfile.DIRTYPE
            nested.mode = 0o700
            tar.addfile(nested)
            entry = tarfile.TarInfo("sql/operator/verify-versions.sql")
            entry.size = 2
            entry.mode = 0o600
            tar.addfile(entry, io.BytesIO(b"ok"))
            implicit = tarfile.TarInfo("sql/implicit/check.sql")
            implicit.size = 2
            implicit.mode = 0o600
            tar.addfile(implicit, io.BytesIO(b"ok"))
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.umask(0o077)
            try:
                launch.extract(data.getvalue(), Path(tmp) / "out")
            finally:
                os.umask(previous)
            out = Path(tmp) / "out"
            for directory in (out / "sql", out / "sql" / "operator", out / "sql" / "implicit"):
                self.assertEqual(0o755, stat.S_IMODE(directory.stat().st_mode), str(directory))
            for item in (out / "sql" / "operator" / "verify-versions.sql",
                         out / "sql" / "implicit" / "check.sql"):
                self.assertEqual(0o644, stat.S_IMODE(item.stat().st_mode), str(item))

    def test_archive_expansion_limit(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as tar:
            item = tarfile.TarInfo("large")
            item.size = 100
            tar.addfile(item, io.BytesIO(b"x" * 100))
        with tempfile.TemporaryDirectory() as tmp, patch.object(launch, "MAX_EXPANDED", 99):
            with self.assertRaisesRegex(launch.CIError, "expanded_archive"):
                launch.extract(data.getvalue(), Path(tmp) / "out")

    def test_ci_change_in_content_path_or_mode_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root / "check.sh"
            p.write_text("exit 0")
            original = launch.tree_hash(root)
            p.write_text("exit 1")
            self.assertNotEqual(original, launch.tree_hash(root))
            p.write_text("exit 0")
            p.chmod(0o755)
            self.assertNotEqual(original, launch.tree_hash(root))

    def test_child_does_not_inherit_credentials_or_actions_channels(self):
        with patch.dict(os.environ, {"CI_S3_SECRET_ACCESS_KEY": "private", "GITHUB_TOKEN": "private",
                                    "GH_BOT_WORKFLOW_TOKEN": "private", "CI_SOURCE_REPOSITORY": "private",
                                    "GITHUB_OUTPUT": "/should/not/be/passed"}):
            output = launch.run([sys.executable, "-c", "import os,json;print(json.dumps(dict(os.environ)))"],
                                io.BytesIO(), capture=True)
        child = json.loads(output)
        self.assertNotIn("CI_S3_SECRET_ACCESS_KEY", child)
        self.assertNotIn("GITHUB_TOKEN", child)
        self.assertNotIn("GH_BOT_WORKFLOW_TOKEN", child)
        self.assertNotIn("CI_SOURCE_REPOSITORY", child)
        self.assertNotIn("GITHUB_OUTPUT", child)

    def test_failed_command_output_stays_private(self):
        log = io.BytesIO()
        with self.assertRaisesRegex(launch.CIError, "^command_failed$"):
            launch.run([sys.executable, "-c", "print('private source fragment');raise SystemExit(3)"], log)
        self.assertIn(b"private source fragment", log.getvalue())

    def test_timeout_and_output_limit_are_errors(self):
        with self.assertRaisesRegex(launch.CIError, "command_timeout"):
            launch.run([sys.executable, "-c", "import time;time.sleep(5)"], io.BytesIO(), timeout=0.1)
        with self.assertRaisesRegex(launch.CIError, "command_output_limit"):
            launch.run([sys.executable, "-c", "print('x'*1000)"], io.BytesIO(), limit=10)

    def test_signature_preserves_external_port_path_and_both_auth_headers(self):
        url, headers = launch.s3_headers("https://s3.example.org:55555", "run/a b.txt", b"hello",
                                        "ACCESS", "SECRET", "GATE", "us-east-1",
                                        dt.datetime(2026, 10, 26, tzinfo=dt.timezone.utc), bucket="test-bucket")
        self.assertEqual(url, "https://s3.example.org:55555/test-bucket/run/a%20b.txt")
        self.assertEqual(headers["host"], "s3.example.org:55555")
        self.assertEqual(headers["x-ci-token"], "GATE")
        self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-ci-token", headers["Authorization"])
        self.assertNotIn("SECRET", headers["Authorization"])
        # Golden value independently generated with botocore 1.40.76 S3SigV4Auth.
        self.assertTrue(headers["Authorization"].endswith(
            "Signature=a1a4c0d96afe788e3fc5319d732db0ef18239d2e65f7b0183c481392db41a104"))

    def test_invalid_endpoint_and_header_injection_are_rejected(self):
        for endpoint in ("http://s3.example.org", "https://user:pass@s3.example.org", "https://s3.example.org/path"):
            with self.assertRaises(launch.CIError):
                launch.s3_headers(endpoint, "key", b"", "A", "S", "G", "us-east-1", bucket="test-bucket")
        with self.assertRaises(launch.CIError):
            launch.s3_headers("https://s3.example.org", "key", b"", "A", "S", "gate\r\nattack", "us-east-1", bucket="test-bucket")

    def test_completion_marker_is_last_and_not_written_on_partial_upload(self):
        settings = {"CI_S3_ENDPOINT": "https://s3.example.org", "CI_S3_ACCESS_KEY_ID": "A",
                    "CI_S3_SECRET_ACCESS_KEY": "S", "CI_S3_GATE_TOKEN": "G",
                    "CI_S3_BUCKET": "test-bucket", "CI_S3_REGION": "us-east-1"}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, settings):
            root = Path(tmp)
            for name in ("result.json", "manifest.json", "execution.log.gz"):
                (root / name).write_bytes(b"{}")
            with patch.object(launch, "request", return_value=b"") as request:
                launch.upload(root, "prefix")
                self.assertTrue(request.call_args_list[-1].args[0].endswith("/result.json"))
            with patch.object(launch, "request", side_effect=launch.CIError("failed")) as request, \
                    patch.object(launch.time, "sleep"):
                with self.assertRaisesRegex(launch.CIError, "evidence_upload_failed"):
                    launch.upload(root, "prefix")
                self.assertTrue(all(not c.args[0].endswith("/result.json") for c in request.call_args_list))


if __name__ == "__main__":
    unittest.main()
