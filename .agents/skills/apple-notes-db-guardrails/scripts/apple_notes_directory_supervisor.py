#!/usr/bin/env python3
"""Launch Apple Notes DB writes with a packaged directory-creation supervisor."""

from __future__ import annotations

import argparse
import array
import fcntl
import importlib.util
import json
import os
import secrets
import signal
import socket
import stat
import subprocess
import shutil
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Iterable


HELPER_PATH = Path(__file__).with_name("apple_notes_db.py")
SUPERVISOR_SHUTDOWN_GRACE_SECONDS = 0.5
WORKER_SHUTDOWN_GRACE_SECONDS = 0.5
SUPERVISOR_POLL_SECONDS = 0.1
SOURCE_PREFIX = ".apple-notes-create-supervisor-source-"
DESTINATION_PREFIX = ".apple-notes-create-"
WORKER_SUPERVISOR_FD = 9
TERMINATION_SIGNALS = frozenset(
    {
        signal.SIGHUP,
        signal.SIGINT,
        signal.SIGTERM,
    }
)
LAUNCH_BLOCKED_SIGNALS = TERMINATION_SIGNALS.union({signal.SIGCHLD})
SPAWN_DEFAULT_SIGNALS = TERMINATION_SIGNALS.union({signal.SIGCHLD})
BLOCKABLE_SIGNALS = frozenset(signal.valid_signals()).difference(
    {
        signal.SIGKILL,
        signal.SIGSTOP,
    }
)
WAIT_STATUS_UNAVAILABLE = -1
WORKER_RETURN_CODE_UNAVAILABLE = 1


def _load_helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "packaged_apple_notes_db_for_supervisor",
        HELPER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load packaged helper: {HELPER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


HELPER = _load_helper()


def _bounded_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:512]


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
) -> tuple[dict[str, object], os.stat_result]:
    request = json.loads(payload.decode("utf-8"))
    if type(request) is not dict:
        raise ValueError("directory supervisor request is not an object")
    if (
        request.get("schema") != HELPER.DIRECTORY_CREATOR_REQUEST_SCHEMA
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
        or request.get("parent_identity") != HELPER._identity(opened)
        or request.get("parent_access_policy") != HELPER._access_policy(opened)
    ):
        raise ValueError("directory supervisor parent binding changed")
    return request, opened


def _mkdir_owner_private_at(parent_fd: int, name: str) -> None:
    """Create one 0700 directory without inheriting a caller's stricter umask."""

    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, BLOCKABLE_SIGNALS)
    previous_umask: int | None = None
    try:
        previous_umask = os.umask(0)
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    finally:
        if previous_umask is not None:
            os.umask(previous_umask)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _serve_one_request(
    channel: socket.socket,
    payload: bytes,
    parent_descriptors: list[int],
) -> None:
    request_id: str | None = None
    source_name: str | None = None
    destination_name: str | None = None
    directory_fd: int | None = None
    published = False
    parent_fd: int | None = None
    try:
        if len(parent_descriptors) != 1:
            raise ValueError("directory supervisor expected exactly one parent FD")
        parent_fd = parent_descriptors.pop()
        request, parent_opened = _validate_request(payload, parent_fd)
        request_id = str(request["request_id"])

        # The returned object is opened before it is atomically published under
        # the protocol-visible staging name. The first randomized name remains
        # private to this supervisor transaction.
        source_name = f"{SOURCE_PREFIX}{secrets.token_hex(24)}"
        destination_name = f"{DESTINATION_PREFIX}{secrets.token_hex(24)}"
        _mkdir_owner_private_at(parent_fd, source_name)
        directory_fd = os.open(
            source_name,
            HELPER._directory_open_flags(),
            dir_fd=parent_fd,
        )
        os.set_inheritable(directory_fd, False)
        os.fchmod(directory_fd, 0o700)
        created = os.fstat(directory_fd)
        source_named = os.stat(
            source_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(created.st_mode)
            or not HELPER._same_identity(created, source_named)
            or stat.S_IMODE(created.st_mode) != 0o700
            or created.st_uid != os.geteuid()
            or list(os.listdir(directory_fd))
        ):
            raise RuntimeError("created directory failed the private-source binding")

        HELPER._rename_directory_no_replace_syscall_at(
            parent_fd,
            source_name,
            destination_name,
        )
        published = True
        named = os.stat(
            destination_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        opened_after = os.fstat(directory_fd)
        parent_after = os.fstat(parent_fd)
        if (
            not HELPER._same_identity(created, named)
            or not HELPER._same_identity(named, opened_after)
            or HELPER._identity(parent_opened) != HELPER._identity(parent_after)
            or HELPER._access_policy(parent_opened)
            != HELPER._access_policy(parent_after)
            or HELPER._access_policy(created) != HELPER._access_policy(opened_after)
        ):
            raise RuntimeError("published directory failed terminal binding")

        _send_response(
            channel,
            {
                "schema": HELPER.DIRECTORY_CREATOR_RESPONSE_SCHEMA,
                "request_id": request_id,
                "status": "created",
                "basename": destination_name,
                "proof": {
                    "schema": "apple-notes-identity-bound-directory-creation/v1",
                    "creation_authority": (
                        "packaged-supervisor-open-before-atomic-noreplace-publication"
                    ),
                    "actual_created_object_descriptor_returned": True,
                    "namespace_exclusive_during_handoff": True,
                    "parent_identity": HELPER._identity(parent_after),
                    "parent_access_policy": HELPER._access_policy(parent_after),
                    "directory_identity": HELPER._identity(opened_after),
                    "directory_access_policy": HELPER._access_policy(opened_after),
                    "publication_primitive": (
                        "platform-atomic-directory-rename-no-replace"
                    ),
                },
            },
            directory_fd=directory_fd,
        )
    except BaseException as exc:
        failure_basename = destination_name if published else source_name
        response: dict[str, object] = {
            "schema": HELPER.DIRECTORY_CREATOR_RESPONSE_SCHEMA,
            "request_id": request_id,
            "status": "failed-after-create",
            "basename": failure_basename,
            "details": {
                "mutation_performed": source_name is not None,
                "retry_safe": False,
                "cleanup_state": (
                    "retained" if source_name is not None else "not-needed"
                ),
                "creation_authority": (
                    "packaged-supervisor-open-before-atomic-noreplace-publication"
                ),
                "provider_install_state": (
                    "published" if published else "prepublication"
                ),
                "provider_staging_basename": failure_basename,
                "recovery_locators": {
                    "packaged_directory_supervisor": {
                        "stage": "serve-request",
                        "error": _bounded_error(exc),
                        "published": published,
                        "basename": failure_basename,
                    }
                },
            },
        }
        if request_id is not None:
            try:
                _send_response(
                    channel,
                    response,
                    directory_fd=directory_fd,
                )
            except BaseException:
                pass
    finally:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass
        _close_fds(parent_descriptors)


def _serve(supervisor_fd: int) -> int:
    try:
        os.setsid()
    except OSError:
        pass
    with socket.socket(fileno=supervisor_fd) as channel:
        channel.settimeout(SUPERVISOR_POLL_SECONDS)
        if channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM:
            return 72
        while True:
            try:
                payload, ancillary, flags, _ = channel.recvmsg(
                    HELPER.DIRECTORY_CREATOR_MAX_MESSAGE_BYTES,
                    socket.CMSG_SPACE(
                        array.array("i").itemsize
                        * HELPER.DIRECTORY_CREATOR_MAX_RECEIVED_FDS
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
            descriptors = HELPER._received_rights_descriptors(ancillary)
            if flags & (
                getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)
            ):
                _close_fds(descriptors)
                continue
            _serve_one_request(channel, payload, descriptors)


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
    """Small wait/kill handle for one posix_spawn-owned worker PID."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        try:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.returncode = WORKER_RETURN_CODE_UNAVAILABLE
            return self.returncode
        if waited == 0:
            return None
        self.returncode = _returncode_from_wait_status(status)
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


def _open_descriptor_inventory() -> list[int]:
    try:
        candidates: Iterable[int] = sorted(
            int(name)
            for name in os.listdir("/dev/fd")
            if name.isascii() and name.isdigit()
        )
    except OSError:
        soft_limit = int(os.sysconf("SC_OPEN_MAX"))
        if soft_limit <= 0:
            soft_limit = 1024
        candidates = range(3, min(soft_limit, 1_048_576))
    opened: list[int] = []
    for descriptor in candidates:
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError:
            continue
        opened.append(descriptor)
    return opened


def _spawn_worker(
    helper_path: Path,
    command: list[str],
    *,
    python_bin: str,
    client_fd: int,
    child_signal_mask: set[signal.Signals],
) -> _SpawnedWorker:
    resolved_python = shutil.which(python_bin)
    if resolved_python is None:
        raise OSError(f"Cannot resolve Python executable: {python_bin}")
    worker_supervisor_fd = (
        WORKER_SUPERVISOR_FD + 1
        if client_fd == WORKER_SUPERVISOR_FD
        else WORKER_SUPERVISOR_FD
    )
    argv = [
        resolved_python,
        "-B",
        os.fspath(helper_path),
        *command,
        "--directory-creator-fd",
        str(worker_supervisor_fd),
    ]
    file_actions: list[tuple[int, ...]] = [
        (
            os.POSIX_SPAWN_DUP2,
            client_fd,
            worker_supervisor_fd,
        )
    ]
    file_actions.extend(
        (os.POSIX_SPAWN_CLOSE, descriptor)
        for descriptor in _open_descriptor_inventory()
        if descriptor > 2 and descriptor != worker_supervisor_fd
    )
    pid = os.posix_spawn(
        resolved_python,
        argv,
        {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        file_actions=file_actions,
        setsid=True,
        setsigmask=child_signal_mask,
        setsigdef=SPAWN_DEFAULT_SIGNALS,
    )
    return _SpawnedWorker(pid)


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
                signal.signal(signal.SIGCHLD, previous_sigchld_handler)
                for signum, handler in previous_handlers.items():
                    signal.signal(signum, handler)
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                _close_unrelated_fds({0, 1, 2, server_fd})
                service_status = _serve(server_fd)
            except BaseException:
                pass
            os._exit(service_status)

        server.close()
        server = None
        worker = _spawn_worker(
            helper_path,
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
