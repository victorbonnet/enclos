"""Files a person sends with a message (ADR 0076, proposed), standard library only.

The bridge sends `message.in` with `files`, then every byte of them in
`message.part`s, in order. This writes them in the channel's own folder in the
sandbox home, `<socket folder>/incoming/<agent>/<random>/`, opened one folder
at a time without following a link, each file made new; and once every
declared byte came, hands the message and its files' paths to the adapter.
A message whose parts do not follow, or whose connection ends first, is
removed and never given to the runtime: the bridge sends it again whole.
"""

import base64
import binascii
import os
import re
import unicodedata
import uuid
from typing import Any, Optional

MAX_FILES = 4
MAX_FILE_BYTES = 10_000_000
MAX_PART_BYTES = 45_000
MAX_NAME_CHARS = 120
MAX_NAME_BYTES = 255
# Extension and the one media type it is sent as (the protocol crate's FILE_TYPES).
TYPES = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp",
    ".gif": "image/gif", ".pdf": "application/pdf", ".md": "text/markdown", ".txt": "text/plain",
    ".csv": "text/csv", ".log": "text/plain", ".json": "application/json", ".xml": "application/xml",
    ".yaml": "application/yaml", ".yml": "application/yaml", ".toml": "application/toml",
    ".py": "text/plain", ".sh": "text/plain", ".zip": "application/zip", ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel", ".ppt": "application/vnd.ms-powerpoint",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
_FOLDER = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class Refused(Exception):
    """Why a message with files is not given to the runtime; `code` is the protocol's."""

    def __init__(self, message_id: str, code: str, reason: str):
        super().__init__(reason)
        self.message_id = message_id
        self.code = code


def check_files(files: Any) -> None:
    """A message's declared files, as the bridge checks them; raises ValueError."""
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError(f"files must list 1 to {MAX_FILES} files")
    for f in files:
        if not isinstance(f, dict):
            raise ValueError("a file is not an object")
        name, mime, size = f.get("name"), f.get("mime"), f.get("size")
        if (not isinstance(name, str) or not name or name in (".", "..") or "/" in name or "\\" in name
                or len(name) > MAX_NAME_CHARS or len(name.encode("utf-8")) > MAX_NAME_BYTES
                or name.strip() != name
                or any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in name)):
            raise ValueError("a file's name is not one plain component")
        stem, dot, ext = name.rpartition(".")
        if not stem or not dot or TYPES.get(f".{ext.lower()}") != mime:
            raise ValueError("a file's type is not one an agent takes, or not its name's")
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_FILE_BYTES:
            raise ValueError(f"a file holds 1 to {MAX_FILE_BYTES} bytes")


def check_part(message: dict[str, Any]) -> None:
    """A `message.part`'s fields, before its bytes are decoded; raises ValueError."""
    if not isinstance(message.get("message"), str) or not message["message"]:
        raise ValueError("message is missing")
    for field, top in (("file", MAX_FILES - 1), ("offset", MAX_FILE_BYTES)):
        value = message.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= top:
            raise ValueError(f"{field} is out of range")
    data = message.get("data")
    if (not isinstance(data, str) or not 0 < len(data) <= (MAX_PART_BYTES + 2) // 3 * 4
            or not re.fullmatch(r"[A-Za-z0-9_-]+", data)):
        raise ValueError("data is not 1 to 45,000 bytes of unpadded base64url")


def _plain(name: str) -> str:
    """`name` as a folder's entry: ASCII letters, digits, `.`, `_`, `-` and spaces, no leading dot."""
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name).lstrip(". ") or "file"


def _disk_name(n: int, name: str) -> str:
    """A file's name on disk: its number, then its name made plain."""
    return f"{n + 1}-{_plain(name)}"


def _open_folder(parent: int, name: str) -> int:
    """Folder `name` of `parent`, made if missing, opened without following a link."""
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    return os.open(name, _FOLDER, dir_fd=parent)


class _Message:
    def __init__(self, message: dict[str, Any], parent: int, folder: str, path: str):
        self.message = message
        self.files = message["files"]
        self.parent, self.folder = parent, folder
        self.fd = os.open(folder, _FOLDER, dir_fd=parent)
        self.names = [_disk_name(n, f["name"]) for n, f in enumerate(self.files)]
        self.paths = [os.path.join(path, folder, name) for name in self.names]
        self.at = 0
        self.offset = 0
        self.out: Optional[int] = None

    def write(self, data: bytes) -> None:
        if self.out is None:
            self.out = os.open(self.names[self.at], _NEW_FILE, 0o600, dir_fd=self.fd)
        view = memoryview(data)
        while view:
            view = view[os.write(self.out, view):]

    def close(self) -> None:
        if self.out is not None:
            os.close(self.out)
            self.out = None

    def remove(self) -> None:
        """Every file of it, and its folder, through the folders it opened."""
        self.close()
        for name in self.names:
            try:
                os.unlink(name, dir_fd=self.fd)
            except FileNotFoundError:
                pass
        os.close(self.fd)
        try:
            os.rmdir(self.folder, dir_fd=self.parent)
        except OSError:
            pass
        os.close(self.parent)


class Receiver:
    """The message with files being received on the bridge's connection."""

    def __init__(self, socket_path: str, agent: str):
        self._home = os.path.dirname(socket_path)
        self._agent = _plain(agent)
        self._current: Optional[_Message] = None

    def begin(self, message: dict[str, Any]) -> None:
        """A `message.in` with files: its folder is made, its bytes awaited."""
        self.drop()
        path = os.path.join(self._home, "incoming", self._agent)
        try:
            top = os.open(self._home, _FOLDER)
            try:
                incoming = _open_folder(top, "incoming")
            finally:
                os.close(top)
            try:
                parent = _open_folder(incoming, self._agent)
            finally:
                os.close(incoming)
            try:
                folder = uuid.uuid4().hex
                os.mkdir(folder, 0o700, dir_fd=parent)
                self._current = _Message(message, parent, folder, path)
            except OSError:
                os.close(parent)
                raise
        except OSError as e:
            raise Refused(message["id"], "internal", f"the files cannot be written: {e.strerror}") from None

    def part(self, message: dict[str, Any]):
        """Writes a `message.part`; the message and its files' paths, types and
        names once every byte came, else None. A part of no message being
        received (one the runtime has, or one refused) is passed over."""
        current = self._current
        if current is None or current.message["id"] != message["message"]:
            return None
        of = current.message["id"]
        try:
            data = base64.urlsafe_b64decode(message["data"] + "=" * (-len(message["data"]) % 4))
        except (binascii.Error, ValueError):
            data = b""
        size = current.files[current.at]["size"]
        if (message["file"] != current.at or message["offset"] != current.offset or not data
                or len(data) > MAX_PART_BYTES or current.offset + len(data) > size):
            self.drop()
            raise Refused(of, "bad_message", f"expected file {current.at} from byte {current.offset}")
        try:
            current.write(data)
        except OSError as e:
            self.drop()
            raise Refused(of, "internal", f"the files cannot be written: {e.strerror}") from None
        current.offset += len(data)
        if current.offset == size:
            current.close()
            current.at += 1
            current.offset = 0
        if current.at < len(current.files):
            return None
        self._current = None
        os.close(current.fd)
        os.close(current.parent)
        return (current.message, current.paths, [f["mime"] for f in current.files],
                [f["name"] for f in current.files])

    def drop(self) -> Optional[str]:
        """Removes the message being received, whose connection ended or which
        was refused; its id, if there was one."""
        current, self._current = self._current, None
        if current is None:
            return None
        current.remove()
        return current.message["id"]
