"""Small trusted launcher; project build/test logic lives in the source repository.

No third-party Python packages. Private command output never goes to Actions.
This is for owner-approved source commits, not hostile public pull requests:
Docker-in-Docker is privileged and is not a VM security boundary.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_LOG = 32 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")


def validate_config(env):
    required = ("GH_BOT_WORKFLOW_TOKEN", "CI_SOURCE_REPOSITORY", "CI_RUNNER_REPOSITORY",
                "CI_ALLOWED_ACTORS", "CI_CONTROL_REF", "CI_S3_ENDPOINT", "CI_S3_BUCKET",
                "CI_S3_ACCESS_KEY_ID", "CI_S3_SECRET_ACCESS_KEY", "CI_S3_GATE_TOKEN", "CI_S3_REGION")
    for key in required:
        if not env.get(key):
            raise CIError("missing_configuration:" + key)
    for key in ("CI_SOURCE_REPOSITORY", "CI_RUNNER_REPOSITORY"):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", env[key]):
            raise CIError("invalid_repository_configuration:" + key)
    if env.get("GITHUB_REPOSITORY") != env["CI_RUNNER_REPOSITORY"]:
        raise CIError("runner_repository_not_allowed")
    try:
        actors = json.loads(env["CI_ALLOWED_ACTORS"])
    except (ValueError, TypeError) as error:
        raise CIError("invalid_actor_configuration") from error
    if not isinstance(actors, list) or not actors or any(not isinstance(x, str) or not x for x in actors):
        raise CIError("invalid_actor_configuration")
    if env.get("GITHUB_ACTOR") not in actors:
        raise CIError("actor_not_allowed")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", env["CI_S3_BUCKET"]):
        raise CIError("invalid_bucket_configuration")
    if not re.fullmatch(r"[A-Za-z0-9-]+", env["CI_S3_REGION"]):
        raise CIError("invalid_region_configuration")


class CIError(Exception):
    """Only controlled, non-secret codes may reach the public console."""


ERROR_HINTS = {
    "http_request_failed": "HTTP or network request failed.",
    "source_commit_not_found": "Source commit was not found or is inaccessible.",
    "source_archive_failed": "Source archive could not be downloaded.",
    "source_archive_redirect_missing": "Archive response did not contain the expected redirect.",
    "invalid_archive_redirect": "Archive redirect was rejected.",
    "canonical_ci_missing": "The configured control ref does not contain the canonical CI directory.",
    "ci_definition_differs_from_main": "CI directories differ: update the tested branch from the trusted control ref.",
    "invalid_source_sha": "source_sha must be a full lowercase 40-character commit SHA.",
    "unsupported_event": "Unsupported event type.",
    "pipeline_not_allowed": "Requested pipeline is not allowed.",
    "unsupported_manifest": "Unsupported canonical CI manifest version.",
    "invalid_pipeline_script": "Invalid pipeline script in the canonical manifest.",
    "invalid_pipeline_timeout": "Invalid pipeline timeout in the canonical manifest.",
    "invalid_image_reference": "An image reference is not pinned to a valid digest.",
    "image_digest_missing": "A resolved image digest was not found.",
    "inner_daemon_not_ready": "The isolated Docker daemon did not become ready.",
    "command_failed": "A build or execution command failed; inspect the private execution log.",
    "command_timeout": "A command exceeded its timeout.",
    "command_output_limit": "A command exceeded its output limit.",
    "pipeline_failed": "The pipeline failed; inspect the private execution log.",
    "evidence_collection_failed": "Evidence could not be collected from the worker.",
    "evidence_upload_failed": "Evidence upload failed; no successful CI status was published.",
    "evidence_upload_limit": "Evidence exceeds the upload size or file-count limit.",
    "invalid_s3_endpoint": "CI_S3_ENDPOINT must be an HTTPS origin without path, query or credentials.",
    "invalid_bucket_configuration": "CI_S3_BUCKET has an invalid format.",
    "invalid_header_value": "A configured header contains forbidden line breaks.",
    "response_too_large": "An HTTP response exceeded its size limit.",
    "expanded_archive_too_large": "An archive exceeded its expansion limit.",
    "unsafe_archive_path": "An archive contains an unsafe path.",
    "archive_links_not_allowed": "An archive contains a link or special entry.",
    "duplicate_archive_entry": "An archive contains a duplicate file.",
    "ci_symlink_not_allowed": "The canonical CI directory contains a link.",
    "run_interrupted": "The run was interrupted.",
}


def public_failure(stage, error):
    """Emit fixed diagnostic text; never echo error strings, URLs or bodies."""
    raw_code = str(error) if isinstance(error, CIError) else ""
    code = raw_code if raw_code in ERROR_HINTS else "unexpected_error"
    hint = ERROR_HINTS.get(code, "Unexpected launcher error; no private exception text was printed.")
    current, seen, http_status = error, set(), None
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, urllib.error.HTTPError) and type(current.code) is int and 100 <= current.code <= 599:
            http_status = current.code
            break
        current = current.__cause__ or current.__context__
    if http_status is not None:
        if http_status in (401, 403):
            hint += " Check credentials and permissions for this stage."
        elif http_status == 404:
            hint += " Check the configured repository/ref/object and read permissions."
        elif http_status == 429:
            hint += " The remote service rate limit was reached."
    detail = {"stage": stage, "code": code, "http_status": http_status}
    suffix = " http_status=" + str(http_status) if http_status else ""
    print("Private CI: stage=" + stage + " code=" + code + suffix + " - " + hint)
    return detail


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CIError("unexpected_redirect")


def request(url, *, headers=None, data=None, method="GET", limit=MAX_ARCHIVE):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=60) as response:
            body = response.read(limit + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        raise CIError("http_request_failed") from error
    if len(body) > limit:
        raise CIError("response_too_large")
    return body


def github(path, token, *, data=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "Content-Type": "application/json",
               "User-Agent": "private-source-ci", "X-GitHub-Api-Version": "2022-11-28"}
    return json.loads(request("https://api.github.com/repos/" + os.environ["CI_SOURCE_REPOSITORY"] + "/" + path,
                              headers=headers, data=None if data is None else json.dumps(data).encode(),
                              method="GET" if data is None else "POST"))


def inputs(event_name, event):
    if event_name == "workflow_dispatch":
        value = event.get("inputs", {})
    elif event_name == "repository_dispatch" and event.get("action") == "private-source-ci":
        value = event.get("client_payload", {})
    else:
        raise CIError("unsupported_event")
    sha, pipeline = value.get("source_sha", ""), value.get("pipeline", "s00")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise CIError("invalid_source_sha")
    if pipeline != "s00":
        raise CIError("pipeline_not_allowed")
    return sha, pipeline


def extract(archive, destination, *, strip_root=False):
    """Reject links/devices/traversal and cap expanded bytes before extracting."""
    destination.mkdir(parents=True, exist_ok=True)
    total, seen = 0, set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if member.name.startswith("/") or ".." in parts:
                raise CIError("unsafe_archive_path")
            if not (member.isdir() or member.isfile()):
                raise CIError("archive_links_not_allowed")
            # docker cp /out/. emits a harmless '.' directory before its files.
            # An empty path must never hide a file, link or special entry.
            if not parts:
                if member.isdir() and member.name in (".", "./"):
                    continue
                raise CIError("unsafe_archive_path")
            if strip_root:
                parts = parts[1:]
            if not parts:
                if member.isdir():
                    continue
                raise CIError("unsafe_archive_path")
            relative = Path(*parts)
            if member.isfile() and relative in seen:
                raise CIError("duplicate_archive_entry")
            seen.add(relative)
            total += member.size
            if total > MAX_EXPANDED or len(seen) > 20000:
                raise CIError("expanded_archive_too_large")
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, target.open("wb") as output:
                    while block := source.read(1024 * 1024):
                        output.write(block)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)


def snapshot(sha, token, destination):
    # The archive endpoint redirects to codeload; never forward the token to an
    # arbitrary redirect. Fetch the validated, GitHub-issued codeload URL directly.
    url = "https://api.github.com/repos/" + os.environ["CI_SOURCE_REPOSITORY"] + "/tarball/" + sha
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                               "User-Agent": "private-source-ci"})
    class Capture(urllib.request.HTTPRedirectHandler):
        location = None
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            self.location = newurl
            return None
    handler = Capture()
    try:
        with urllib.request.build_opener(handler).open(req, timeout=60):
            raise CIError("source_archive_redirect_missing")
    except urllib.error.HTTPError as error:
        if error.code not in (301, 302, 303, 307, 308):
            raise CIError("source_archive_failed") from error
    parsed = urllib.parse.urlsplit(handler.location or "")
    if (parsed.scheme != "https" or parsed.netloc != "codeload.github.com"
            or parsed.username or parsed.password):
        raise CIError("invalid_archive_redirect")
    archive = request(handler.location)
    extract(archive, destination, strip_root=True)


def tree_hash(root):
    if not root.is_dir():
        raise CIError("canonical_ci_missing")
    values = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise CIError("ci_symlink_not_allowed")
        if path.is_file():
            values.append((path.relative_to(root).as_posix(),
                           bool(path.stat().st_mode & 0o111),
                           hashlib.sha256(path.read_bytes()).hexdigest()))
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def run(args, log, *, timeout=120, capture=False, limit=MAX_LOG):
    """Bound command output/time; do not inherit credentials into CLI children."""
    child_env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG") if key in os.environ}
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=child_env, start_new_session=True)
    output, size, started = bytearray(), 0, time.monotonic()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            if time.monotonic() - started > timeout:
                raise CIError("command_timeout")
            for key, _ in selector.select(0.25):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                size += len(chunk)
                if size > limit:
                    raise CIError("command_output_limit")
                if capture:
                    output.extend(chunk)
                else:
                    log.write(chunk)
        rc = process.wait(timeout=max(1, timeout - (time.monotonic() - started)))
        if rc:
            raise CIError("command_failed")
        return bytes(output)
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()


def status(sha, pipeline, state, token):
    github("statuses/" + sha, token, data={"state": state, "context": "external-ci/" + pipeline,
            "description": "Private CI: " + state,
            "target_url": "https://github.com/" + os.environ["CI_RUNNER_REPOSITORY"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"]})


def s3_headers(endpoint, key, body, access, secret, gate, region, now=None, *, bucket):
    parsed = urllib.parse.urlsplit(endpoint)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise CIError("invalid_s3_endpoint")
    now = now or dt.datetime.now(dt.timezone.utc)
    date, stamp = now.strftime("%Y%m%d"), now.strftime("%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise CIError("invalid_bucket_configuration")
    path = "/" + bucket + "/" + urllib.parse.quote(key, safe="/~-._")
    digest = hashlib.sha256(body).hexdigest()
    headers = {"host": parsed.netloc, "x-amz-content-sha256": digest,
               "x-amz-date": stamp, "x-ci-token": gate}
    if any("\r" in v or "\n" in v for v in headers.values()):
        raise CIError("invalid_header_value")
    names = ";".join(sorted(headers))
    canonical = "PUT\n" + path + "\n\n" + "".join(k + ":" + headers[k].strip() + "\n" for k in sorted(headers)) + "\n" + names + "\n" + digest
    scope = date + "/" + region + "/s3/aws4_request"
    to_sign = "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hashlib.sha256(canonical.encode()).hexdigest()
    signing = ("AWS4" + secret).encode()
    for part in (date, region, "s3", "aws4_request"):
        signing = hmac.new(signing, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(signing, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + access + "/" + scope + ", SignedHeaders=" + names + ", Signature=" + signature
    return endpoint.rstrip("/") + path, headers


def upload(directory, prefix):
    env = os.environ
    files = [p for p in sorted(directory.rglob("*")) if p.is_file() and not p.is_symlink()]
    if len(files) > 256 or sum(p.stat().st_size for p in files) > MAX_ARCHIVE:
        raise CIError("evidence_upload_limit")
    # result.json is the completion marker: upload it only after every evidence
    # object and manifest. A partial upload must never publish a success result.
    files.sort(key=lambda p: (p.name == "result.json", p.as_posix()))
    for path in files:
        if not path.is_file() or path.is_symlink():
            continue
        body = path.read_bytes()
        url, headers = s3_headers(env["CI_S3_ENDPOINT"], prefix + "/" + path.relative_to(directory).as_posix(),
                                 body, env["CI_S3_ACCESS_KEY_ID"], env["CI_S3_SECRET_ACCESS_KEY"],
                                 env["CI_S3_GATE_TOKEN"], env["CI_S3_REGION"], bucket=env["CI_S3_BUCKET"])
        for attempt in range(3):
            try:
                request(url, headers=headers, data=body, method="PUT", limit=1024 * 1024)
                break
            except CIError:
                if attempt == 2:
                    raise CIError("evidence_upload_failed")
                time.sleep(2 ** attempt)


def execute(source, control, output, pipeline, log, manifest):
    config = json.loads((control / "manifest.json").read_text())
    if config.get("version") != 1:
        raise CIError("unsupported_manifest")
    spec = config["pipelines"][pipeline]
    script = spec["script"]
    if not re.fullmatch(r"pipelines/[a-z0-9-]+\.sh", script) or not (control / script).is_file():
        raise CIError("invalid_pipeline_script")
    timeout = spec["timeout_seconds"]
    if not isinstance(timeout, int) or not 30 <= timeout <= 1200:
        raise CIError("invalid_pipeline_timeout")
    images = {}
    for name in ("node", "docker_cli", "dind"):
        ref = config["images"][name]
        if not isinstance(ref, str) or not re.fullmatch(r"[a-z0-9./:_-]+@sha256:[0-9a-f]{64}", ref):
            raise CIError("invalid_image_reference")
        run(["docker", "pull", ref], log, timeout=180)
        resolved = json.loads(run(["docker", "image", "inspect", ref, "--format", "{{json .RepoDigests}}"], log, capture=True))
        if not resolved or "@sha256:" not in resolved[0]:
            raise CIError("image_digest_missing")
        images[name] = resolved[0]
    manifest["images"] = images
    tag = "private-ci-worker:" + uuid.uuid4().hex
    suffix = uuid.uuid4().hex
    network, daemon, worker = ("ci-net-" + suffix, "ci-docker-" + suffix, "ci-work-" + suffix)
    try:
        run(["docker", "build", "--build-arg", "NODE_IMAGE=" + images["node"],
             "--build-arg", "DOCKER_CLI_IMAGE=" + images["docker_cli"], "-t", tag, str(control)], log, timeout=180)
        run(["docker", "network", "create", network], log)
        run(["docker", "run", "-d", "--privileged", "--name", daemon, "--network", network,
             "--network-alias", "docker", "--memory", "3g", "--cpus", "2", "--pids-limit", "1024",
             "-e", "DOCKER_TLS_CERTDIR=", images["dind"]], log)
        run(["docker", "create", "--name", worker, "--network", network, "--memory", "3g",
             "--cpus", "2", "--pids-limit", "1024", "-e", "DOCKER_HOST=tcp://docker:2375",
             "-e", "TESTCONTAINERS_HOST_OVERRIDE=docker", tag, "bash", "/ci/" + script], log)
        run(["docker", "cp", str(source) + "/.", worker + ":/source"], log)
        run(["docker", "cp", str(control) + "/.", worker + ":/ci"], log)
        for _ in range(60):
            try:
                run(["docker", "exec", daemon, "docker", "info"], log, timeout=5)
                break
            except CIError:
                time.sleep(1)
        else:
            raise CIError("inner_daemon_not_ready")
        manifest["execution_started"] = True
        execution_error = None
        try:
            run(["docker", "start", "--attach", worker], log, timeout=timeout)
            # docker start -a does not reliably convey the container exit status.
            exit_code = run(["docker", "inspect", worker, "--format", "{{.State.ExitCode}}"], log, capture=True).strip()
            if exit_code != b"0":
                execution_error = "pipeline_failed"
        except CIError as error:
            execution_error = str(error)
            run(["docker", "stop", "--time", "5", worker], log)
        try:
            archive = run(["docker", "cp", worker + ":/out/.", "-"], log, capture=True, limit=MAX_ARCHIVE)
            extract(archive, output / "evidence")
        except CIError:
            manifest["evidence_incomplete"] = True
            if not execution_error:
                raise CIError("evidence_collection_failed")
        if execution_error:
            raise CIError(execution_error)
    finally:
        for args in (["docker", "rm", "-f", "-v", worker, daemon], ["docker", "network", "rm", network],
                     ["docker", "image", "rm", tag]):
            try:
                run(args, log)
            except CIError:
                pass


def main():
    os.umask(0o077)
    sha = pipeline = None
    stage = "read_event"
    diagnostics = []
    final = "error"
    error_code = "launcher_failed"
    env = os.environ
    try:
        validate_config(env)
    except CIError as error:
        # validate_config emits only fixed codes and names from its fixed key
        # lists, never values, actor names or exception text from JSON parsing.
        print("Private CI: invalid configuration or caller [" + str(error) + "]")
        return 1
    def interrupted(signum, frame):
        raise CIError("run_interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with tempfile.TemporaryDirectory(prefix="private-ci-") as tmp:
        root = Path(tmp)
        output = root / "output"
        output.mkdir()
        manifest = {"version": 1, "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "evidence_incomplete": False, "execution_started": False,
                    "launcher_sha": env.get("GITHUB_SHA"), "platform": "linux/amd64"}
        try:
            sha, pipeline = inputs(env["GITHUB_EVENT_NAME"], json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text()))
            # Resolve and validate source SHA before publishing any status.
            stage = "fetch_source_commit"
            if github("commits/" + sha, env["GH_BOT_WORKFLOW_TOKEN"])["sha"] != sha:
                raise CIError("source_commit_not_found")
            stage = "publish_pending_status"
            status(sha, pipeline, "pending", env["GH_BOT_WORKFLOW_TOKEN"])
            stage = "resolve_control_ref"
            trusted_sha = github("commits/" + urllib.parse.quote(env["CI_CONTROL_REF"], safe=""), env["GH_BOT_WORKFLOW_TOKEN"])["sha"]
            manifest.update(source_repository=env["CI_SOURCE_REPOSITORY"], source_sha=sha, control_sha=trusted_sha, pipeline=pipeline,
                            run_id=env["GITHUB_RUN_ID"], run_attempt=env.get("GITHUB_RUN_ATTEMPT", "1"))
            stage = "fetch_source_archive"
            snapshot(sha, env["GH_BOT_WORKFLOW_TOKEN"], root / "source")
            stage = "fetch_control_archive"
            snapshot(trusted_sha, env["GH_BOT_WORKFLOW_TOKEN"], root / "trusted")
            stage = "compare_ci"
            control = root / "trusted/.ci/runner"
            manifest["ci_tree_sha256"] = tree_hash(control)
            if tree_hash(root / "source/.ci/runner") != manifest["ci_tree_sha256"]:
                raise CIError("ci_definition_differs_from_main")
            with (output / "execution.log").open("wb") as log:
                stage = "execute_pipeline"
                execute(root / "source", control, output, pipeline, log, manifest)
            final, error_code = "success", None
        except Exception as error:
            diagnostic = public_failure(stage, error)
            diagnostics.append(diagnostic)
            error_code = diagnostic["code"]
            final = "failure" if error_code == "pipeline_failed" else "error"
        finally:
            manifest.update(finished_at=dt.datetime.now(dt.timezone.utc).isoformat(), state=final,
                            error_code=error_code, diagnostics=diagnostics)
            log_path = output / "execution.log"
            if log_path.exists():
                with log_path.open("rb") as log, gzip.open(output / "execution.log.gz", "wb") as compressed:
                    compressed.write(log.read())
                log_path.unlink()
            manifest["artifacts"] = [{"path": p.relative_to(output).as_posix(), "bytes": p.stat().st_size,
                                      "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                                     for p in sorted(output.rglob("*")) if p.is_file() and not p.is_symlink()]
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
            result = {"version": 1, "state": final, "error_code": error_code,
                      "diagnostics": diagnostics,
                      "source_sha": sha, "pipeline": pipeline,
                      "evidence_incomplete": manifest["evidence_incomplete"]}
            (output / "result.json").write_text(json.dumps(result, indent=2))
            if sha and pipeline:
                prefix = sha + "/" + env["GITHUB_RUN_ID"] + "-" + env.get("GITHUB_RUN_ATTEMPT", "1")
                try:
                    upload(output, prefix)
                except Exception as error:
                    diagnostics.append(public_failure("upload_evidence", error))
                    final, error_code = "error", "evidence_upload_failed"
                try:
                    status(sha, pipeline, final, env["GH_BOT_WORKFLOW_TOKEN"])
                except Exception as error:
                    diagnostics.append(public_failure("publish_final_status", error))
                    final, error_code = "error", "status_publish_failed"
        # No exception text, source paths, URLs or private output on stdout.
        print("Private CI: " + final)
        return 0 if final == "success" else 1


if __name__ == "__main__":
    try:
        code = main()
    except Exception as error:
        # A failed finalizer must not dump a traceback into the public run.
        public_failure("finalize_launcher", error)
        print("Private CI: launcher error")
        code = 1
    raise SystemExit(code)