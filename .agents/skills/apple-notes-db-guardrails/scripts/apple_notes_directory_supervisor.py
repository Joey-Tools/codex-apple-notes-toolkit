#!/usr/bin/env python3
"""Launch Apple Notes DB writes with a packaged directory-creation supervisor."""

from __future__ import annotations

import argparse
import array
import hashlib
import json
import os
import select
import signal
import socket
import stat
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Iterable


HELPER_PATH = Path(__file__).with_name("apple_notes_db.py")
HELPER_SOURCE_MAX_BYTES = 2 * 1024 * 1024
HELPER_SOURCE_FRAME_MAGIC = b"apple-notes-helper-source/v1"
HELPER_SOURCE_DELIVERY_TIMEOUT_SECONDS = 5.0
HELPER_SOURCE_WRITE_CHUNK_BYTES = 64 * 1024
_DARWIN_ACCESS_POLICY_FLAG_MASK = sum(
    (
        0x00000002,  # UF_IMMUTABLE
        0x00000004,  # UF_APPEND
        0x00000080,  # UF_DATAVAULT
        0x00020000,  # SF_IMMUTABLE
        0x00040000,  # SF_APPEND
        0x00080000,  # SF_RESTRICTED
        0x00100000,  # SF_NOUNLINK
    )
)
SUPERVISOR_SHUTDOWN_GRACE_SECONDS = 0.5
WORKER_SHUTDOWN_GRACE_SECONDS = 0.5
SUPERVISOR_POLL_SECONDS = 0.1
DESTINATION_PREFIX = ".apple-notes-create-"
TERMINATION_SIGNALS = frozenset(
    {
        signal.SIGHUP,
        signal.SIGINT,
        signal.SIGTERM,
    }
)
LAUNCH_BLOCKED_SIGNALS = TERMINATION_SIGNALS.union({signal.SIGCHLD})
SPAWN_DEFAULT_SIGNALS = TERMINATION_SIGNALS.union({signal.SIGCHLD})
WAIT_STATUS_UNAVAILABLE = -1
WORKER_RETURN_CODE_UNAVAILABLE = 1
WORKER_BOOTSTRAP_SOURCE = """
import hashlib
import json
import os
import signal
import sys

HELPER_SOURCE_FRAME_MAGIC = b"apple-notes-helper-source/v1"
HELPER_SOURCE_MAX_BYTES = 2 * 1024 * 1024

def read_exact(descriptor, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            raise ValueError("supervised-worker helper source frame is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

try:
    (
        helper_display_path,
        raw_source_fd,
        raw_client_fd,
        raw_signal_mask,
        raw_signal_defaults,
        raw_expected_size,
        expected_sha256,
        *command,
    ) = sys.argv[1:]
    source_fd = int(raw_source_fd)
    client_fd = int(raw_client_fd)
    expected_size = int(raw_expected_size)
    decoded_mask = json.loads(raw_signal_mask)
    decoded_defaults = json.loads(raw_signal_defaults)
    valid_signals = {int(signum) for signum in signal.valid_signals()}
    for label, values in (
        ("mask", decoded_mask),
        ("defaults", decoded_defaults),
    ):
        if (
            type(values) is not list
            or len(values) > len(valid_signals)
            or any(type(signum) is not int for signum in values)
            or len(set(values)) != len(values)
            or any(signum not in valid_signals for signum in values)
        ):
            raise ValueError(f"invalid supervised-worker signal {label}")
    if client_fd < 0:
        raise ValueError("invalid supervised-worker channel")
    if (
        source_fd < 0
        or expected_size < 1
        or expected_size > HELPER_SOURCE_MAX_BYTES
        or len(expected_sha256) != 64
    ):
        raise ValueError("invalid supervised-worker helper source metadata")
    os.fstat(client_fd)
    os.fstat(source_fd)
    try:
        header = read_exact(
            source_fd,
            len(HELPER_SOURCE_FRAME_MAGIC) + 8 + hashlib.sha256().digest_size,
        )
        magic_end = len(HELPER_SOURCE_FRAME_MAGIC)
        if header[:magic_end] != HELPER_SOURCE_FRAME_MAGIC:
            raise ValueError("supervised-worker helper source frame magic mismatch")
        framed_size = int.from_bytes(header[magic_end : magic_end + 8], "big")
        framed_digest = header[magic_end + 8 :]
        if (
            framed_size < 1
            or framed_size > HELPER_SOURCE_MAX_BYTES
            or framed_size != expected_size
            or framed_digest.hex() != expected_sha256
        ):
            raise ValueError("supervised-worker helper source frame metadata mismatch")
        helper_source = read_exact(source_fd, framed_size)
        if os.read(source_fd, 1):
            raise ValueError("supervised-worker helper source frame has trailing bytes")
        if hashlib.sha256(helper_source).digest() != framed_digest:
            raise ValueError("supervised-worker helper source digest mismatch")
    finally:
        os.close(source_fd)
    for signum in decoded_defaults:
        signal.signal(signum, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK, set(decoded_mask))
except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
    print(
        json.dumps(
            {
                "error": str(exc),
                "error_code": "directory-supervisor-worker-bootstrap-failed",
            },
            ensure_ascii=True,
        ),
        file=sys.stderr,
    )
    raise SystemExit(1) from exc

sys.argv = [
    helper_display_path,
    *command,
    "--directory-creator-fd",
    str(client_fd),
]
namespace = {
    "__name__": "__main__",
    "__file__": helper_display_path,
    "__package__": None,
    "__cached__": None,
    "__captured_source_sha256__": expected_sha256,
}
exec(
    compile(
        helper_source,
        helper_display_path,
        "exec",
        dont_inherit=True,
    ),
    namespace,
    namespace,
)
"""


@dataclass(frozen=True)
class _CapturedHelperSource:
    display_path: Path
    source: bytes
    sha256: str
    identity: tuple[int, int, int]
    access_policy: tuple[int, int, int, int]


def _helper_source_identity(value: os.stat_result) -> tuple[int, int, int]:
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode))


def _helper_source_access_policy(
    value: os.stat_result,
) -> tuple[int, int, int, int]:
    return (
        stat.S_IMODE(value.st_mode),
        value.st_uid,
        value.st_gid,
        int(getattr(value, "st_flags", 0)) & _DARWIN_ACCESS_POLICY_FLAG_MASK,
    )


def _read_helper_source_pass(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, HELPER_SOURCE_WRITE_CHUNK_BYTES))
        if not chunk:
            raise RuntimeError("packaged helper source became truncated during capture")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise RuntimeError("packaged helper source grew during bounded capture")
    return b"".join(chunks)


def _capture_helper_source(path: Path) -> _CapturedHelperSource:
    """Capture one stable no-follow helper byte object for every consumer."""

    display_path = Path(os.path.abspath(os.fspath(path)))
    try:
        before_path = os.stat(display_path, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError(
            f"Cannot inspect packaged helper: {display_path}: {exc}"
        ) from exc
    if not stat.S_ISREG(before_path.st_mode):
        raise RuntimeError(f"Packaged helper is not a regular file: {display_path}")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or cloexec is None or nonblock is None:
        raise RuntimeError(
            "Packaged helper capture requires O_NOFOLLOW, O_CLOEXEC, and O_NONBLOCK"
        )
    try:
        descriptor = os.open(
            display_path,
            os.O_RDONLY | nofollow | cloexec | nonblock,
        )
    except OSError as exc:
        raise RuntimeError(
            f"Cannot open packaged helper safely: {display_path}: {exc}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _helper_source_identity(opened) != _helper_source_identity(before_path)
            or _helper_source_access_policy(opened)
            != _helper_source_access_policy(before_path)
        ):
            raise RuntimeError(
                f"Packaged helper changed across no-follow open: {display_path}"
            )
        expected_size = opened.st_size
        if expected_size < 1 or expected_size > HELPER_SOURCE_MAX_BYTES:
            raise RuntimeError(
                "Packaged helper size is outside the bounded capture contract: "
                f"{display_path}: {expected_size}"
            )
        first = _read_helper_source_pass(descriptor, expected_size)
        middle = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_helper_source_pass(descriptor, expected_size)
        after = os.fstat(descriptor)
        try:
            after_path = os.stat(display_path, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError(
                f"Cannot terminally inspect packaged helper: {display_path}: {exc}"
            ) from exc
    finally:
        os.close(descriptor)

    identity = _helper_source_identity(opened)
    access_policy = _helper_source_access_policy(opened)
    if any(
        _helper_source_identity(value) != identity
        for value in (middle, after, after_path)
    ):
        raise RuntimeError(
            f"Packaged helper identity changed during capture: {display_path}"
        )
    if any(
        _helper_source_access_policy(value) != access_policy
        for value in (middle, after, after_path)
    ):
        raise RuntimeError(
            f"Packaged helper access policy changed during capture: {display_path}"
        )
    if any(value.st_size != expected_size for value in (middle, after, after_path)):
        raise RuntimeError(
            f"Packaged helper size changed during capture: {display_path}"
        )
    if first != second:
        raise RuntimeError(
            f"Packaged helper content changed during capture: {display_path}"
        )
    return _CapturedHelperSource(
        display_path=display_path,
        source=first,
        sha256=hashlib.sha256(first).hexdigest(),
        identity=identity,
        access_policy=access_policy,
    )


def _load_helper(
    capture: _CapturedHelperSource,
    *,
    module_name: str = "packaged_apple_notes_db_for_supervisor",
) -> ModuleType:
    module = ModuleType(module_name)
    module.__file__ = os.fspath(capture.display_path)
    module.__package__ = ""
    module.__captured_source_sha256__ = capture.sha256
    sys.modules[module_name] = module
    try:
        code = compile(
            capture.source,
            os.fspath(capture.display_path),
            "exec",
            dont_inherit=True,
        )
        exec(code, module.__dict__, module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def _helper_source_frame(capture: _CapturedHelperSource) -> bytes:
    return b"".join(
        (
            HELPER_SOURCE_FRAME_MAGIC,
            len(capture.source).to_bytes(8, "big"),
            bytes.fromhex(capture.sha256),
            capture.source,
        )
    )


def _write_helper_source_frame(
    descriptor: int,
    frame: bytes,
    *,
    timeout_seconds: float = HELPER_SOURCE_DELIVERY_TIMEOUT_SECONDS,
) -> None:
    """Deliver one bounded frame without waiting forever for the worker."""

    if timeout_seconds <= 0:
        raise ValueError("helper source delivery timeout must be positive")
    if len(frame) > (
        len(HELPER_SOURCE_FRAME_MAGIC)
        + 8
        + hashlib.sha256().digest_size
        + HELPER_SOURCE_MAX_BYTES
    ):
        raise ValueError("helper source frame exceeds the bounded delivery contract")
    os.set_blocking(descriptor, False)
    payload = memoryview(frame)
    offset = 0
    deadline = time.monotonic() + timeout_seconds
    while offset < len(payload):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out delivering captured helper source")
        try:
            written = os.write(
                descriptor,
                payload[offset : offset + HELPER_SOURCE_WRITE_CHUNK_BYTES],
            )
        except InterruptedError:
            continue
        except BlockingIOError:
            written = 0
        if written:
            offset += written
            continue
        try:
            _, writable, _ = select.select(
                [],
                [descriptor],
                [],
                min(remaining, SUPERVISOR_POLL_SECONDS),
            )
        except InterruptedError:
            continue
        if not writable and time.monotonic() >= deadline:
            raise TimeoutError("timed out delivering captured helper source")


HELPER_CAPTURE = _capture_helper_source(HELPER_PATH)
HELPER = _load_helper(HELPER_CAPTURE)


def _close_fds(descriptors: Iterable[int]) -> None:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _close_unrelated_fds(keep: set[int]) -> None:
    """Close every inherited descriptor outside the service's fixed allowlist."""

    try:
        candidates: Iterable[int] = [
            int(name)
            for name in os.listdir("/dev/fd")
            if name.isascii() and name.isdigit()
        ]
    except OSError:
        soft_limit = int(os.sysconf("SC_OPEN_MAX"))
        candidates = range(3, min(soft_limit, 1_048_576))
    for descriptor in candidates:
        if descriptor in keep:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass


def _send_response(
    channel: socket.socket,
    payload: dict[str, object],
    *,
    directory_fd: int | None = None,
) -> None:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    ancillary: list[tuple[int, int, bytes]] = []
    if directory_fd is not None:
        ancillary.append(
            (
                socket.SOL_SOCKET,
                socket.SCM_RIGHTS,
                array.array("i", [directory_fd]),
            )
        )
    sent = channel.sendmsg([encoded], ancillary)
    if sent != len(encoded):
        raise RuntimeError("directory supervisor response was truncated")


def _validate_request(
    payload: bytes,
    parent_fd: int,
    helper_module: ModuleType,
) -> tuple[dict[str, object], os.stat_result]:
    request = json.loads(payload.decode("utf-8"))
    if type(request) is not dict:
        raise ValueError("directory supervisor request is not an object")
    if (
        request.get("schema") != helper_module.DIRECTORY_CREATOR_REQUEST_SCHEMA
        or request.get("operation") != "create-owner-private-directory"
        or request.get("prefix") != DESTINATION_PREFIX
        or request.get("mode") != 0o700
        or request.get("expected_uid") != os.geteuid()
    ):
        raise ValueError("directory supervisor request violates the closed contract")
    request_id = request.get("request_id")
    if (
        type(request_id) is not str
        or not request_id
        or len(request_id) > 128
        or not request_id.isascii()
    ):
        raise ValueError("directory supervisor request ID is invalid")
    opened = os.fstat(parent_fd)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or request.get("parent_identity") != helper_module._identity(opened)
        or request.get("parent_access_policy") != helper_module._access_policy(opened)
    ):
        raise ValueError("directory supervisor parent binding changed")
    return request, opened


def _serve_one_request(
    channel: socket.socket,
    payload: bytes,
    parent_descriptors: list[int],
    helper_module: ModuleType,
) -> None:
    request_id: str | None = None
    parent_fd: int | None = None
    try:
        if len(parent_descriptors) != 1:
            raise ValueError("directory supervisor expected exactly one parent FD")
        parent_fd = parent_descriptors.pop()
        request, _ = _validate_request(payload, parent_fd, helper_module)
        request_id = str(request["request_id"])

        # No supported platform API atomically creates a directory and returns
        # the descriptor for that exact object.  Fail before mkdir rather than
        # make a probabilistic same-UID exclusion claim.
        _send_response(
            channel,
            {
                "schema": helper_module.DIRECTORY_CREATOR_RESPONSE_SCHEMA,
                "request_id": request_id,
                "status": helper_module.DIRECTORY_CREATOR_UNAVAILABLE_STATUS,
                "basename": None,
                "proof": None,
                "details": (
                    helper_module._packaged_directory_creator_unavailable_details()
                ),
            },
        )
    except BaseException:
        if request_id is not None:
            try:
                _send_response(
                    channel,
                    {
                        "schema": helper_module.DIRECTORY_CREATOR_RESPONSE_SCHEMA,
                        "request_id": request_id,
                        "status": helper_module.DIRECTORY_CREATOR_UNAVAILABLE_STATUS,
                        "basename": None,
                        "proof": None,
                        "details": (
                            helper_module._packaged_directory_creator_unavailable_details()
                        ),
                    },
                )
            except BaseException:
                pass
    finally:
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass
        _close_fds(parent_descriptors)


def _serve(supervisor_fd: int, helper_module: ModuleType) -> int:
    with socket.socket(fileno=supervisor_fd) as channel:
        channel.settimeout(SUPERVISOR_POLL_SECONDS)
        if channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM:
            return 72
        while True:
            try:
                payload, ancillary, flags, _ = channel.recvmsg(
                    helper_module.DIRECTORY_CREATOR_MAX_MESSAGE_BYTES,
                    socket.CMSG_SPACE(
                        array.array("i").itemsize
                        * helper_module.DIRECTORY_CREATOR_MAX_RECEIVED_FDS
                    ),
                )
            except socket.timeout:
                if os.getppid() == 1:
                    return 0
                continue
            except InterruptedError:
                continue
            if not payload:
                return 0
            descriptors = helper_module._received_rights_descriptors(ancillary)
            if flags & (
                getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)
            ):
                _close_fds(descriptors)
                continue
            _serve_one_request(channel, payload, descriptors, helper_module)


def _wait_pid(pid: int, deadline: float) -> int | None:
    while True:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return WAIT_STATUS_UNAVAILABLE
        if waited == pid:
            return status
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.01)


def _terminate_pid(pid: int, grace_seconds: float) -> int | None:
    status = _wait_pid(pid, time.monotonic())
    if status is not None:
        return status
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    status = _wait_pid(pid, time.monotonic() + grace_seconds)
    if status is not None:
        return status
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return _wait_pid(pid, time.monotonic() + grace_seconds)


def _returncode_from_wait_status(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    raise RuntimeError(f"worker entered unsupported wait status: {status}")


class _SpawnedWorker:
    """Small wait/kill handle for one close-fds spawn-owned worker PID."""

    def __init__(
        self,
        pid: int,
        *,
        process: subprocess.Popen[bytes] | None = None,
    ) -> None:
        self.pid = pid
        self.returncode: int | None = None
        self._process = process

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        try:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.returncode = WORKER_RETURN_CODE_UNAVAILABLE
            if self._process is not None:
                self._process.returncode = self.returncode
            return self.returncode
        if waited == 0:
            return None
        self.returncode = _returncode_from_wait_status(status)
        if self._process is not None:
            self._process.returncode = self.returncode
        return self.returncode

    def wait(self, *, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            returncode = self.poll()
            if returncode is not None:
                return returncode
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(
                    cmd="apple-notes-supervised-worker",
                    timeout=timeout,
                )
            time.sleep(0.01)


def _spawn_worker(
    helper_capture: _CapturedHelperSource,
    command: list[str],
    *,
    python_bin: str,
    client_fd: int,
    child_signal_mask: set[signal.Signals],
) -> _SpawnedWorker:
    resolved_python = shutil.which(python_bin)
    if resolved_python is None:
        raise OSError(f"Cannot resolve Python executable: {python_bin}")
    source_read_fd, source_write_fd = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    worker: _SpawnedWorker | None = None
    try:
        argv = [
            resolved_python,
            "-I",
            "-B",
            "-S",
            "-c",
            WORKER_BOOTSTRAP_SOURCE,
            os.fspath(helper_capture.display_path),
            str(source_read_fd),
            str(client_fd),
            json.dumps(
                sorted(int(signum) for signum in child_signal_mask),
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            json.dumps(
                sorted(int(signum) for signum in SPAWN_DEFAULT_SIGNALS),
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            str(len(helper_capture.source)),
            helper_capture.sha256,
            *command,
        ]
        process = subprocess.Popen(
            argv,
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            close_fds=True,
            pass_fds=(client_fd, source_read_fd),
            start_new_session=True,
        )
        worker = _SpawnedWorker(process.pid, process=process)
        os.close(source_read_fd)
        source_read_fd = -1
        _write_helper_source_frame(
            source_write_fd,
            _helper_source_frame(helper_capture),
        )
    except BaseException:
        if source_write_fd >= 0:
            _close_fds((source_write_fd,))
            source_write_fd = -1
        if worker is not None:
            _terminate_worker(worker, WORKER_SHUTDOWN_GRACE_SECONDS)
        raise
    finally:
        _close_fds(
            descriptor
            for descriptor in (source_read_fd, source_write_fd)
            if descriptor >= 0
        )
    if worker is None:
        raise RuntimeError("supervised worker spawn produced no process handle")
    return worker


def _drain_pending_termination_signals(
    managed_signals: set[signal.Signals],
    first_signal: int | None,
) -> int | None:
    pending = set(signal.sigpending()).intersection(managed_signals)
    for pending_signal in sorted(pending):
        signum = int(signal.sigwait({pending_signal}))
        if first_signal is None:
            first_signal = signum
    return first_signal


def _terminate_worker(
    worker: _SpawnedWorker,
    grace_seconds: float,
) -> None:
    if worker.poll() is not None:
        return
    try:
        os.killpg(worker.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        worker.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(worker.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        worker.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        raise RuntimeError("supervised worker did not reap after SIGKILL")


def run_supervised(
    helper_path: Path,
    command: list[str],
    *,
    python_bin: str,
) -> int:
    if not command:
        raise ValueError("a helper command is required")
    if any(
        argument == "--directory-creator-fd"
        or argument.startswith("--directory-creator-fd=")
        for argument in command
    ):
        raise ValueError(
            "the packaged launcher owns --directory-creator-fd; "
            "do not supply it explicitly"
        )
    if not hasattr(os, "fork"):
        raise RuntimeError("the packaged directory supervisor requires POSIX")

    requested_helper_path = Path(os.path.abspath(os.fspath(helper_path)))
    if requested_helper_path != HELPER_CAPTURE.display_path:
        raise ValueError(
            "the production launcher is bound to its packaged helper; "
            "custom --helper paths are unsupported"
        )
    return _run_supervised_capture(
        HELPER_CAPTURE,
        HELPER,
        command,
        python_bin=python_bin,
    )


def _run_supervised_capture(
    helper_capture: _CapturedHelperSource,
    helper_module: ModuleType,
    command: list[str],
    *,
    python_bin: str,
) -> int:
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, LAUNCH_BLOCKED_SIGNALS)
    managed_signals = {
        signum for signum in TERMINATION_SIGNALS if signum not in previous_mask
    }
    previous_handlers = {signum: signal.getsignal(signum) for signum in managed_signals}
    previous_sigchld_handler = signal.getsignal(signal.SIGCHLD)
    first_signal: int | None = None
    primary_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    return_code: int | None = None
    client: socket.socket | None = None
    server: socket.socket | None = None
    service_pid: int | None = None
    worker: _SpawnedWorker | None = None

    def latch_termination_signal(signum: int, _frame: object) -> None:
        nonlocal first_signal
        if first_signal is None:
            first_signal = signum

    try:
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        for signum in managed_signals:
            signal.signal(signum, latch_termination_signal)
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        client.set_inheritable(False)
        server.set_inheritable(False)
        service_pid = os.fork()
        if service_pid == 0:
            service_status = 73
            try:
                client.close()
                server_fd = server.detach()
                try:
                    os.setsid()
                except OSError:
                    pass
                signal.signal(signal.SIGCHLD, previous_sigchld_handler)
                for signum, handler in previous_handlers.items():
                    signal.signal(signum, handler)
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                _close_unrelated_fds({0, 1, 2, server_fd})
                service_status = _serve(server_fd, helper_module)
            except BaseException:
                pass
            os._exit(service_status)

        server.close()
        server = None
        worker = _spawn_worker(
            helper_capture,
            command,
            python_bin=python_bin,
            client_fd=client.fileno(),
            child_signal_mask=set(previous_mask),
        )
        signal.pthread_sigmask(
            signal.SIG_SETMASK,
            set(previous_mask).union({signal.SIGCHLD}),
        )
        while True:
            return_code = worker.poll()
            if first_signal is not None or return_code is not None:
                break
            time.sleep(SUPERVISOR_POLL_SECONDS)
    except BaseException as exc:
        primary_error = exc
    finally:
        if worker is not None and worker.poll() is None:
            try:
                _terminate_worker(worker, WORKER_SHUTDOWN_GRACE_SECONDS)
            except BaseException as exc:
                cleanup_error = exc
        if client is not None:
            try:
                client.close()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if server is not None:
            try:
                server.close()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if service_pid is not None:
            try:
                service_status = _terminate_pid(
                    service_pid,
                    SUPERVISOR_SHUTDOWN_GRACE_SECONDS,
                )
                if service_status is None:
                    raise RuntimeError("directory supervisor service did not reap")
                if service_status == WAIT_STATUS_UNAVAILABLE:
                    raise RuntimeError(
                        "directory supervisor service status is unavailable "
                        "after ECHILD"
                    )
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
        first_signal = _drain_pending_termination_signals(managed_signals, first_signal)
        try:
            signal.signal(signal.SIGCHLD, previous_sigchld_handler)
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    if first_signal is not None:
        os.kill(os.getpid(), first_signal)
        return 128 + first_signal
    if primary_error is not None:
        raise primary_error
    if cleanup_error is not None:
        raise cleanup_error
    if return_code is None:
        raise RuntimeError("supervised worker produced no terminal status")
    return return_code if return_code >= 0 else 128 + abs(return_code)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, default=HELPER_PATH)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    try:
        return run_supervised(args.helper, command, python_bin=args.python)
    except (OSError, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "error": str(exc),
                    "error_code": "directory-supervisor-launch-failed",
                },
                ensure_ascii=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
