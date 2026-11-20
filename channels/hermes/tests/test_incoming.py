"""The files a person sends with a message: checked, written only in the
channel's own folder, never through a link, and removed when incomplete."""

import base64
import os
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from enclos import incoming, protocol  # noqa: E402


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def message_in(files) -> dict:
    return {"v": 1, "type": "message.in", "id": "m-1", "conversation": "c-1", "person": "p",
            "text": "look", "files": files}


def part(file: int, offset: int, data: bytes, message: str = "m-1") -> dict:
    return {"v": 1, "type": "message.part", "id": os.urandom(4).hex(), "message": message,
            "file": file, "offset": offset, "data": b64(data)}


class Checks(unittest.TestCase):
    def test_canonical_names(self):
        import json
        from pathlib import Path
        corpus = Path(__file__).resolve().parents[3] / "crates/enclos-protocol/tests/fixtures/incoming_names.json"
        for case in json.loads(corpus.read_text()):
            with self.subTest(case=case):
                try:
                    incoming.check_name(case["name"])
                    accepted = True
                except ValueError:
                    accepted = False
                self.assertEqual(accepted, case["accepted"])

    def test_count_size_name_and_type_are_checked(self):
        one = {"name": "a.txt", "mime": "text/plain", "size": 1}
        incoming.check_files([one] * 4)
        for files in ([], [one] * 5, [{**one, "size": incoming.MAX_FILE_BYTES + 1}], [{**one, "size": 0}],
                      [{**one, "name": "../a.txt"}], [{**one, "name": ".."}], [{**one, "name": "a‮.txt"}],
                      [{**one, "mime": "text/html", "name": "a.html"}], [{**one, "mime": "image/png"}]):
            with self.assertRaises(ValueError, msg=files):
                incoming.check_files(files)

    def test_the_decoder_refuses_a_bad_part_or_file_list(self):
        import json
        good = part(0, 0, b"hi")
        protocol.decode_from_bridge(json.dumps(good).encode())
        for bad in ({**good, "data": "a+b/"}, {**good, "data": ""}, {**good, "file": 4}, {**good, "offset": -1},
                    {**good, "data": "A" * 60_004}):
            with self.assertRaises(protocol.DecodeError):
                protocol.decode_from_bridge(json.dumps(bad).encode())
        with self.assertRaises(protocol.DecodeError):
            protocol.decode_from_bridge(json.dumps(message_in([{"name": "a", "mime": "x", "size": 1}])).encode())


class ReceiverTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.home = os.path.join(self.dir, ".enclos-app")
        os.mkdir(self.home)
        self.receiver = incoming.Receiver(os.path.join(self.home, "main.sock"), "main")

    def folders(self) -> list:
        root = os.path.join(self.home, "incoming", "main")
        return os.listdir(root) if os.path.isdir(root) else []

    def test_files_are_written_in_the_channels_folder_under_plain_names(self):
        self.receiver.begin(message_in([{"name": "a b?.txt", "mime": "text/plain", "size": 5},
                                        {"name": "x.png", "mime": "image/png", "size": 1}]))
        self.assertIsNone(self.receiver.part(part(0, 0, b"hel")))
        self.assertIsNone(self.receiver.part(part(0, 3, b"lo")))
        message, paths, types, names = self.receiver.part(part(1, 0, b"\x89"))
        self.assertEqual(message["id"], "m-1")
        self.assertEqual([os.path.basename(p) for p in paths], ["1-a b_.txt", "2-x.png"])
        self.assertEqual(os.path.dirname(os.path.dirname(paths[0])), os.path.join(self.home, "incoming", "main"))
        with open(paths[0], "rb") as f:
            self.assertEqual(f.read(), b"hello")
        self.assertEqual((types, names), (["text/plain", "image/png"], ["a b?.txt", "x.png"]))

    def test_a_part_out_of_order_or_too_long_removes_the_message(self):
        for parts in ([part(0, 1, b"x")], [part(0, 0, b"abcdef")], [part(0, 0, b"ab"), part(1, 0, b"x")]):
            self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 5},
                                            {"name": "b.txt", "mime": "text/plain", "size": 1}]))
            with self.assertRaises(incoming.Refused) as refused:
                for p in parts:
                    self.receiver.part(p)
            self.assertEqual((refused.exception.code, refused.exception.message_id), ("bad_message", "m-1"))
            self.assertEqual(self.folders(), [])
        # Its later parts are passed over
        self.assertIsNone(self.receiver.part(part(0, 0, b"a")))

    def test_an_unfinished_message_is_removed_when_dropped(self):
        self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 5}]))
        self.receiver.part(part(0, 0, b"ab"))
        self.assertEqual(len(self.folders()), 1)
        self.assertEqual(self.receiver.drop(), "m-1")
        self.assertEqual(self.folders(), [])
        # Nothing left to complete: a later part is passed over
        self.assertIsNone(self.receiver.part(part(0, 2, b"cde")))
        self.assertIsNone(self.receiver.drop())

    def test_expiry_deletion_and_inflight_leases(self):
        msg = message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}])
        self.receiver.begin(msg)
        # Expiry cannot retire reception; confirmed deletion can.
        self.receiver.cleanup(now=10**12)
        received = self.receiver.part(part(0, 0, b"x"))
        self.receiver.admit(received[1])
        self.receiver.cleanup(now=10**12)
        self.assertTrue(os.path.isfile(received[1][0]))
        self.receiver.release(received[1])
        self.receiver.cleanup(conversation="other")
        self.assertTrue(os.path.isfile(received[1][0]))
        self.receiver.cleanup(conversation="c-1")
        self.assertEqual(self.folders(), [])
        # A restarted receiver recovers marked crash leftovers after 24 hours.
        self.receiver.begin(msg)
        self.receiver.part(part(0, 0, b"x"))
        restarted = incoming.Receiver(os.path.join(self.home, "main.sock"), "main")
        restarted.cleanup(now=0)
        self.assertEqual(len(self.folders()), 1)
        restarted.cleanup(now=10**12)
        self.assertEqual(self.folders(), [])

    def test_cleanup_preserves_unknown_leaves_and_links(self):
        self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        self.receiver.drop()
        root = os.path.join(self.home, "incoming", "main")
        outside = os.path.join(self.dir, "unrelated")
        os.mkdir(outside)
        with open(os.path.join(outside, "keep"), "w") as out:
            out.write("keep")
        os.symlink(outside, os.path.join(root, "a" * 32))
        os.mkdir(os.path.join(root, "b" * 32))
        with open(os.path.join(root, "b" * 32, "unknown"), "w") as out:
            out.write("preserve")
        self.receiver.cleanup(now=10**12)
        self.assertEqual(sorted(self.folders()), ["a" * 32, "b" * 32])
        self.assertTrue(os.path.isfile(os.path.join(outside, "keep")))

    def test_expired_crash_metadata_and_legacy_partials(self):
        self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        self.receiver.drop()
        root = os.path.join(self.home, "incoming", "main")
        for i, metadata in enumerate((None, b"", b'{"owner":')):
            leaf = os.path.join(root, str(i) * 32)
            os.mkdir(leaf)
            if metadata is not None:
                with open(os.path.join(leaf, ".enclos-incoming.json"), "wb") as out:
                    out.write(metadata)
            with open(os.path.join(leaf, "1-a.txt"), "wb") as out:
                out.write(b"partial")
        self.receiver.cleanup(now=10**12)
        self.assertEqual(self.folders(), [])

    def test_all_disk_name_classes_expire_in_legacy_and_malformed_leaves(self):
        self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        self.receiver.drop()
        root = os.path.join(self.home, "incoming", "main")
        for original in ("-a.txt", "_a.txt", "1.txt", "a b.txt", " a.txt", "?.txt", "a.b.txt", ".a.txt"):
            for metadata in (None, b'{"owner":'):
                with self.subTest(original=original, metadata=metadata):
                    import uuid
                    leaf = os.path.join(root, uuid.uuid4().hex)
                    os.mkdir(leaf)
                    if metadata is not None:
                        Path(leaf, ".enclos-incoming.json").write_bytes(metadata)
                    Path(leaf, incoming._disk_name(0, original)).write_bytes(b"x")
                    self.receiver.cleanup(now=10**12)
                    self.assertFalse(os.path.exists(leaf))

    def test_malformed_recovery_retains_unexpected_entries_and_symlink_targets(self):
        self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        self.receiver.drop()
        root = Path(self.home, "incoming", "main")
        target = Path(self.dir, "keep.txt")
        target.write_bytes(b"keep")
        for i, unexpected in enumerate(("unknown", "1-.hidden.txt", "1- a.txt", "1-a.txt")):
            leaf = root / (str(i) * 32)
            leaf.mkdir()
            (leaf / ".enclos-incoming.json").write_bytes(b'{"owner":')
            if unexpected == "1-a.txt":
                (leaf / unexpected).symlink_to(target)
            else:
                (leaf / unexpected).write_bytes(b"keep")
            self.receiver.cleanup(now=10**12)
            self.assertTrue(leaf.exists())
        self.assertEqual(target.read_bytes(), b"keep")

    def test_failed_message_open_removes_own_empty_leaf(self):
        from unittest.mock import patch
        with patch("enclos.incoming._Message", side_effect=OSError("open failed")):
            with self.assertRaises(incoming.Refused):
                self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        self.assertEqual(self.folders(), [])

    def test_confirmed_delete_removes_admitted_paths_and_retry_errors(self):
        from unittest.mock import patch
        self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        received = self.receiver.part(part(0, 0, b"x"))
        self.receiver.admit(received[1])
        with patch("enclos.incoming.os.unlink", side_effect=PermissionError("denied")):
            with self.assertRaises(OSError):
                self.receiver.cleanup(conversation="c-1")
        self.assertTrue(os.path.exists(received[1][0]))
        self.receiver.cleanup(conversation="c-1")
        self.assertFalse(os.path.exists(received[1][0]))

    def test_metadata_wrapper_failure_closes_descriptors(self):
        from unittest.mock import patch
        fd_root = next((p for p in ("/proc/self/fd", "/dev/fd") if os.path.isdir(p)), None)
        before = len(os.listdir(fd_root)) if fd_root else None
        with patch("enclos.incoming.os.fdopen", side_effect=OSError("metadata failed")):
            with self.assertRaises(incoming.Refused):
                self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        if fd_root:
            self.assertEqual(len(os.listdir(fd_root)), before)
        self.assertEqual(self.folders(), [])

    def test_confirmed_delete_drops_partial_reception(self):
        self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 2}]))
        self.receiver.part(part(0, 0, b"x"))
        self.receiver.cleanup(conversation="c-1")
        self.assertEqual(self.folders(), [])
        self.assertIsNone(self.receiver.part(part(0, 1, b"y")))

    def test_unadmitted_completed_copy_can_expire(self):
        self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        self.receiver.part(part(0, 0, b"x"))
        self.receiver.cleanup(now=10**12)
        self.assertEqual(self.folders(), [])

    def test_zero_write_refuses_and_removes_partial_files(self):
        from unittest.mock import patch
        self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        with patch("enclos.incoming.os.write", return_value=0):
            with self.assertRaises(incoming.Refused):
                self.receiver.part(part(0, 0, b"x"))
        self.assertEqual(self.folders(), [])

    def test_a_link_in_place_of_its_folder_is_not_followed(self):
        outside = os.path.join(self.dir, "outside")
        os.mkdir(outside)
        os.symlink(outside, os.path.join(self.home, "incoming"))
        with self.assertRaises(incoming.Refused) as refused:
            self.receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 1}]))
        self.assertEqual(refused.exception.code, "internal")
        self.assertEqual(os.listdir(outside), [])


if __name__ == "__main__":
    unittest.main()
