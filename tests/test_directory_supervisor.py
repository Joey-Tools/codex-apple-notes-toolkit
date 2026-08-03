from __future__ import annotations

import array
import errno
import importlib.util
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR_PATH = (
    REPO_ROOT
    / ".agents"
    / "skills"
    / "apple-notes-db-guardrails"
    / "scripts"
    / "apple_notes_directory_supervisor.py"
)


def _load_supervisor() -> object:
    spec = importlib.util.spec_from_file_location(
        "apple_notes_directory_supervisor_contract_tests",
        SUPERVISOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load packaged directory supervisor")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPERVISOR = _load_supervisor()
HELPER = SUPERVISOR.HELPER


class PackagedDirectorySupervisorTests(unittest.TestCase):
    def _serve_once(
        self,
        root: Path,
    ) -> tuple[dict[str, object], list[int]]:
        parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        parent = os.fstat(parent_fd)
        request = json.dumps(
            {
                "schema": HELPER.DIRECTORY_CREATOR_REQUEST_SCHEMA,
                "request_id": "packaged-supervisor-contract-test",
                "operation": "create-owner-private-directory",
                "prefix": SUPERVISOR.DESTINATION_PREFIX,
                "mode": 0o700,
                "expected_uid": os.geteuid(),
                "parent_identity": HELPER._identity(parent),
                "parent_access_policy": HELPER._access_policy(parent),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        received: list[int] = []
        try:
            SUPERVISOR._serve_one_request(
                server,
                request,
                [os.dup(parent_fd)],
                HELPER,
            )
            payload, ancillary, flags, _ = client.recvmsg(
                HELPER.DIRECTORY_CREATOR_MAX_MESSAGE_BYTES,
                socket.CMSG_SPACE(
                    array.array("i").itemsize
                    * HELPER.DIRECTORY_CREATOR_MAX_RECEIVED_FDS
                ),
            )
            self.assertEqual(flags, 0)
            received = HELPER._received_rights_descriptors(ancillary)
            return json.loads(payload.decode("utf-8")), received
        except BaseException:
            HELPER._close_descriptors(received)
            raise
        finally:
            client.close()
            server.close()
            os.close(parent_fd)

    def test_random_name_collision_retries_without_replacing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            collision = root / f"{SUPERVISOR.DESTINATION_PREFIX}{bytes(16).hex()}"
            collision.mkdir(mode=0o700)
            with mock.patch.object(
                SUPERVISOR.os,
                "urandom",
                side_effect=[bytes(16), b"\x01" * 16],
            ):
                response, received = self._serve_once(root)
            try:
                self.assertEqual(response["status"], "created")
                self.assertEqual(
                    response["basename"],
                    f"{SUPERVISOR.DESTINATION_PREFIX}{'01' * 16}",
                )
                self.assertEqual(len(received), 1)
                self.assertTrue(collision.is_dir())
                self.assertEqual(len(list(root.iterdir())), 2)
            finally:
                HELPER._close_descriptors(received)

    def test_open_failure_after_mkdir_retains_randomized_directory(self) -> None:
        original_open = os.open

        def fail_created_directory_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if (
                isinstance(path, str)
                and path.startswith(SUPERVISOR.DESTINATION_PREFIX)
                and dir_fd is not None
            ):
                raise OSError(errno.EIO, "simulated directory open failure")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with mock.patch.object(
                SUPERVISOR.os,
                "open",
                side_effect=fail_created_directory_open,
            ):
                response, received = self._serve_once(root)
            try:
                self.assertEqual(response["status"], "failed-after-create")
                self.assertEqual(received, [])
                self.assertTrue((root / str(response["basename"])).is_dir())
                details = response["details"]
                self.assertTrue(details["mutation_performed"])
                self.assertFalse(details["retry_safe"])
                self.assertEqual(
                    details["cleanup_state"],
                    "preserved-no-identity-safe-directory-unlink",
                )
                locator = details["recovery_locators"]["packaged_directory_supervisor"]
                self.assertEqual(locator["stage"], "created-directory-open")
                self.assertFalse(locator["automatic_cleanup_attempted"])
            finally:
                HELPER._close_descriptors(received)

    def test_response_failure_returns_recovery_fd_and_retains_directory(
        self,
    ) -> None:
        original_send = SUPERVISOR._send_response
        calls = 0

        def fail_first_send(
            channel: socket.socket,
            payload: dict[str, object],
            *,
            directory_fd: int | None = None,
        ) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                self.assertEqual(payload["status"], "created")
                raise OSError(errno.EPIPE, "simulated response failure")
            original_send(channel, payload, directory_fd=directory_fd)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with mock.patch.object(
                SUPERVISOR,
                "_send_response",
                side_effect=fail_first_send,
            ):
                response, received = self._serve_once(root)
            try:
                self.assertEqual(calls, 2)
                self.assertEqual(response["status"], "failed-after-create")
                self.assertEqual(len(received), 1)
                retained = root / str(response["basename"])
                self.assertTrue(retained.is_dir())
                self.assertTrue(
                    HELPER._same_identity(
                        os.fstat(received[0]),
                        os.stat(retained, follow_symlinks=False),
                    )
                )
                locator = response["details"]["recovery_locators"][
                    "packaged_directory_supervisor"
                ]
                self.assertEqual(locator["stage"], "created-directory-response")
                self.assertEqual(locator["descriptor_identity_status"], "observed")
            finally:
                HELPER._close_descriptors(received)


if __name__ == "__main__":
    unittest.main()
