"""The files a person sends with a message: checked, written only in the
channel's own folder, never through a link, and removed when incomplete."""

import base64
import os
import sys
import tempfile
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
