#!/usr/bin/env python3
"""Launch Apple Notes DB writes with a packaged directory-creation supervisor."""

from __future__ import annotations

import argparse
import array
import importlib.util
import json
import os
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Iterable, Iterator


HELPER_PATH = Path(__file__).with_name("apple_notes_db.py")
SUPERVISOR_SHUTDOWN_GRACE_SECONDS = 0.5
WORKER_SHUTDOWN_GRACE_SECONDS = 0.5
SUPERVISOR_POLL_SECONDS = 0.1
SOURCE_PREFIX = ".apple-notes-create-supervisor-source-"
DESTINATION_PREFIX = ".apple-notes-create-"


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


class _SupervisorSignal(BaseException):
    """Convert launcher termination signals into cleanup-owning control flow."""

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


@contextmanager
def _bounded_signal_scope() -> Iterator[None]:
    previous_handlers: dict[int, object] = {}

    def raise_signal(signum: int, _frame: object) -> None:
        raise _SupervisorSignal(signum)

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, raise_signal)
    try:
        yield
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


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
        os.mkdir(source_name, mode=0o700, dir_fd=parent_fd)
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
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.01)
    return None


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


def _terminate_worker(
    worker: subprocess.Popen[bytes],
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
        pass


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

    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    client.set_inheritable(False)
    server.set_inheritable(False)
    service_pid = os.fork()
    if service_pid == 0:
        client.close()
        server_fd = server.detach()
        _close_unrelated_fds({0, 1, 2, server_fd})
        try:
            status = _serve(server_fd)
        except BaseException:
            status = 73
        os._exit(status)

    server.close()
    worker: subprocess.Popen[bytes] | None = None
    try:
        with _bounded_signal_scope():
            worker = subprocess.Popen(
                [
                    python_bin,
                    "-B",
                    os.fspath(helper_path),
                    *command,
                    "--directory-creator-fd",
                    str(client.fileno()),
                ],
                stdin=None,
                stdout=None,
                stderr=None,
                close_fds=True,
                pass_fds=(client.fileno(),),
                start_new_session=True,
            )
            return_code = worker.wait()
        return return_code if return_code >= 0 else 128 + abs(return_code)
    except BaseException:
        if worker is not None:
            try:
                _terminate_worker(worker, WORKER_SHUTDOWN_GRACE_SECONDS)
            except BaseException:
                pass
        raise
    finally:
        client.close()
        try:
            _terminate_pid(service_pid, SUPERVISOR_SHUTDOWN_GRACE_SECONDS)
        except BaseException:
            pass


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
    except _SupervisorSignal as exc:
        return 128 + exc.signum
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
