"""Messages for the bridge kept on disk until it acknowledges them.

One file per message, named by a sequence number then the message's id, so
they are sent again in order after each connection. Written to a temporary
name and renamed, so a crash never leaves half a message.
"""

import json
import os
import re
from typing import Any

_NAME = re.compile(r"^(\d{12})-([0-9a-f-]{36})\.json$")


class Outbox:
    def __init__(self, folder: str, limit: int = 1000):
        self._folder = folder
        self._limit = limit
        os.makedirs(folder, mode=0o700, exist_ok=True)

    def _entries(self) -> list[tuple[int, str, str]]:
        entries = []
        for name in os.listdir(self._folder):
            match = _NAME.match(name)
            if match:
                entries.append((int(match.group(1)), match.group(2), name))
        return sorted(entries)

    def put(self, message: dict[str, Any]) -> bool:
        """Keeps the message; False, keeping nothing, once `limit` are waiting."""
        entries = self._entries()
        if len(entries) >= self._limit:
            return False
        number = entries[-1][0] + 1 if entries else 1
        name = f"{number:012d}-{message['id']}.json"
        temporary = os.path.join(self._folder, f".{name}.tmp")
        with open(temporary, "w", encoding="utf-8") as f:
            json.dump(message, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, os.path.join(self._folder, name))
        return True

    def pending(self) -> list[dict[str, Any]]:
        """Every message not acknowledged yet, oldest first."""
        messages = []
        for _, _, name in self._entries():
            try:
                with open(os.path.join(self._folder, name), encoding="utf-8") as f:
                    messages.append(json.load(f))
            except (OSError, json.JSONDecodeError):
                continue
        return messages

    def acknowledge(self, message_id: str) -> bool:
        for _, entry_id, name in self._entries():
            if entry_id == message_id:
                os.unlink(os.path.join(self._folder, name))
                return True
        return False
