"""Text an agent or a person wrote, checked before another person reads it.

A control character, a bidirectional override or isolate, a zero-width or
other default-ignorable character, a line separator or a blank filler
changes how the text around it reads without showing itself. Names, labels
and question text refuse them; a command, which must be shown exactly as it
runs, shows them instead (``revealed``).

The joiners U+200C and U+200D and the emoji variation selectors U+FE0E and
U+FE0F are part of ordinary text (Persian spelling, joined emoji), so they
count as hidden only where they cannot be: next to ASCII, at an end, or
beside another hidden character. The same rule as enclos-protocol's
``visible`` module and the app's ``Visible``.
"""

_JOINERS = frozenset((0x200C, 0x200D, 0xFE0E, 0xFE0F))
_SINGLE = frozenset(
    (0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x200B, 0x200E,
     0x200F, 0x2800, 0x3164, 0xFEFF, 0xFFA0)
)
_RANGES = (
    (0x180B, 0x180F), (0x2028, 0x202E), (0x2060, 0x206F), (0xFE00, 0xFE0D),
    (0xFFF0, 0xFFFB), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)


def is_joiner(c: str) -> bool:
    """Whether ``c`` is a joiner ordinary text uses between two non-ASCII characters."""
    return ord(c) in _JOINERS


def is_hidden(c: str) -> bool:
    """Whether ``c`` changes how the text around it is shown without being seen,
    wherever it stands (a joiner counts: one character alone cannot say where it stands)."""
    o = ord(c)
    return (
        o < 0x20 or 0x7F <= o <= 0x9F or o in _JOINERS or o in _SINGLE
        or any(lo <= o <= hi for lo, hi in _RANGES)
    )


def _marks(text: str) -> list:
    def plain(i: int) -> bool:
        return 0 <= i < len(text) and ord(text[i]) >= 0x80 and not is_hidden(text[i])

    out = []
    for i, c in enumerate(text):
        o = ord(c)
        if o in (0xFE0E, 0xFE0F):
            hidden = not plain(i - 1)
        elif o in _JOINERS:
            hidden = not (plain(i - 1) and plain(i + 1))
        else:
            hidden = is_hidden(c)
        out.append((c, hidden))
    return out


def has_hidden(text: str, lines: bool = False) -> bool:
    """Whether ``text`` holds a character hidden where it stands, newlines aside when ``lines``."""
    return any(hidden and not (lines and c == "\n") for c, hidden in _marks(text))


def stripped(text: str, lines: bool = False) -> str:
    """``text`` without the characters hidden where they stand (newlines kept when ``lines``)."""
    return "".join(c for c, hidden in _marks(text) if not hidden or (lines and c == "\n"))


def revealed(text: str) -> str:
    """``text`` with each hidden character but a newline written as ⟨U+XXXX⟩ and a tab as ⟨tab⟩."""
    out = []
    for c, hidden in _marks(text):
        if c == "\n":
            out.append("\n")
        elif c == "\t":
            out.append("⟨tab⟩")
        elif hidden:
            out.append("⟨U+%04X⟩" % ord(c))
        else:
            out.append(c)
    return "".join(out)


def bare(text: str) -> str:
    """``text`` without joiners, for telling whether two names read the same."""
    return "".join(c for c in text if not is_joiner(c))
