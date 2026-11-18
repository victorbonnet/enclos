"""Runtime-approval decisions the bridge signs (ADR 0060, proposed; docs/protocol.md).

The bridge signs each person's runtime-approval decision with a key kept
outside every sandbox; this channel acts on a decision only once it has
checked that signature with the bridge's public key, which `enclos runtime
configure --channel app` gives it (MOBILE_APP_BRIDGE_KEY), never the
socket. The agent's token proves nothing about the person, since the agent
can read it: without this check, a program of the sandbox that speaks on
this socket while the bridge is away could approve its own command.

The statement signed is the same as the `enclos-protocol` crate's
(`decision.rs`): each field's UTF-8 bytes after their length as 4 bytes
big-endian. The signature is ECDSA P-256 with SHA-256, `r` then `s`, 64
bytes in base64url; the key is SEC1 uncompressed, in base64url. Checking it
needs the `cryptography` package, which Hermes ships; without it the
channel offers no runtime-approval buttons.
"""

import base64
import binascii
import logging
import time

LABEL = "enclos/runtime-approval/1"
# How old a signed decision may be, and how far ahead of this clock, in
# seconds: the bridge signs it as it sends it, from the same host's clock.
MAX_AGE_SECONDS = 60
MAX_AHEAD_SECONDS = 5

logger = logging.getLogger(__name__)


def statement(agent, conversation, question, request, action, command, reason, patterns, at) -> bytes:
    """The bytes the bridge signs for a decision."""
    fields = [LABEL, agent, conversation, question, request, action, command, reason,
              str(len(patterns)), *patterns, str(at)]
    out = bytearray()
    for field in fields:
        data = field.encode("utf-8")
        out += len(data).to_bytes(4, "big") + data
    return bytes(out)


def _unpadded(text):
    """Bytes of base64url text without padding; ValueError when it is not."""
    if not isinstance(text, str) or "=" in text:
        raise ValueError("not unpadded base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("not unpadded base64url") from None


class Verifier:
    """Checks decisions for `agent` (`sandbox/agent`) against the bridge's
    public key `key` (SEC1, base64url). Raises ImportError without the
    `cryptography` package and ValueError for a key it cannot read."""

    def __init__(self, key, agent):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.exceptions import InvalidSignature
        self._key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _unpadded(key))
        self._algorithm = ec.ECDSA(hashes.SHA256())
        self._der = utils.encode_dss_signature
        self._invalid = InvalidSignature
        self.agent = agent

    def check(self, message, card, now=time.time):
        """None when `message`, a `question.answer`, carries the bridge's
        signature of this very decision on `card`, made in the last minute;
        otherwise why not, for the log."""
        signed = message.get("signed")
        if not isinstance(signed, dict):
            return "it is not signed"
        at, sig = signed.get("at"), signed.get("sig")
        if type(at) is not int or not isinstance(sig, str):
            return "its signature cannot be read"
        current = int(now())
        if at < current - MAX_AGE_SECONDS or at > current + MAX_AHEAD_SECONDS:
            return f"its signature is not fresh (signed at {at}, read at {current})"
        try:
            raw = _unpadded(sig)
        except ValueError:
            return "its signature cannot be read"
        if len(raw) != 64:
            return "its signature cannot be read"
        approval = card.definition["approval"]
        data = statement(self.agent, card.conversation, card.definition["id"], message["id"],
                         message["answer"]["action"], approval["command"], approval["reason"],
                         list(approval.get("patterns", [])), at)
        try:
            self._key.verify(self._der(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                             data, self._algorithm)
        except self._invalid:
            return "its signature does not match this decision and the bridge's key"
        return None


def load(key, sandbox, agent):
    """The verifier for this channel, or None, said in the log, when it
    cannot check decisions: then it offers no runtime-approval buttons."""
    if not key or not sandbox:
        logger.warning("The bridge's key for runtime approvals (MOBILE_APP_BRIDGE_KEY) or the sandbox's "
                       "name (ENCLOS_SANDBOX) is not set: runtime approvals have no app buttons. Run "
                       "`enclos runtime configure <sandbox>/<agent> --channel app` again.")
        return None
    try:
        return Verifier(key, f"{sandbox}/{agent}")
    except ImportError:
        logger.warning("The cryptography package is missing: runtime approvals have no app buttons")
    except ValueError:
        logger.warning("MOBILE_APP_BRIDGE_KEY is not a P-256 key: runtime approvals have no app buttons. "
                       "Run `enclos runtime configure <sandbox>/<agent> --channel app` again.")
    return None
