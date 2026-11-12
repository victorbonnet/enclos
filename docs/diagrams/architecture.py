"""Draws docs/diagrams/{architecture,sandbox}-{light,dark}.svg.

Run from the repository root: uv run --no-project python docs/diagrams/architecture.py
Edit the boxes below, then run it again; both themes always match.
"""

from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).parent
FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif'

THEMES = {
    "dark": dict(bg="#0d1117", panel="#161b22", box="#0d1117", line="#3d444d", text="#e6edf3",
                 sub="#9198a1", later="#6e7681", accent="#4493f8", accent_bg="#121d2f",
                 ok="#3fb950", ok_bg="#12261e", no="#f85149", no_bg="#2d1517"),
    "light": dict(bg="#ffffff", panel="#f6f8fa", box="#ffffff", line="#d1d9e0", text="#1f2328",
                  sub="#59636e", later="#818b98", accent="#0969da", accent_bg="#ddf4ff",
                  ok="#1a7f37", ok_bg="#dafbe1", no="#cf222e", no_bg="#ffebe9"),
}

TITLE = "Every client goes through one core; each sandbox runs as its own services"
SUBTITLE = "No daemon: the CLI writes state and audit, and the service manager keeps each sandbox's proxy and gateway running"

CLIENTS = [  # x, title, lines, kind
    (40, "enclos (CLI)", ["every operation", "milestone 1"], "accent"),
    (420, "enclos ui", ["local web UI", "same audit log; later"], "later"),
    (800, "Host assistants", ["Claude Code, Codex: run the CLI", "with the enclos plugin; later"], "later"),
]
CORE = [
    (60, "State + audit", ["SQLite + JSONL"]),
    (322, "Policy", ["layers, snapshots, compiled"]),
    (584, "Runtime adapters", ["install, login, agents"]),
    (846, "Backend API", ["one implementation each"]),
]
BACKENDS = [
    (60, "Seatbelt", ["macOS, milestone 1"], "solid"),
    (322, "bubblewrap", ["Linux, milestone 3"], "solid"),
    (584, "OpenShell", ["later"], "later"),
    (846, "MicroVM", ["later: libkrun"], "later"),
]
SERVICES = [
    (60, "Sandbox lab", ["Hermes and its agents", "its own home and policy"]),
    (420, "Egress proxy", ["one per sandbox, on the host", "logs every connection"]),
    (780, "Allowed domains", ["at validated addresses", "everything else refused"]),
]

SANDBOX_TITLE = "Everything in a sandbox runs under one compiled policy; only its proxy connects out"
SANDBOX_SUBTITLE = "On macOS, with Seatbelt. Green is allowed and red is refused, by the sandbox's policy."

INSIDE = [  # y, height, title, lines
    (188, 140, "Hermes and its agents", ["the gateway, each session,", "and every process they start"]),
    (342, 130, "Its home", ["read and write: the runtime,", "agents, login, caches"]),
    (486, 120, "Workspaces you grant", ["read and write"]),
]
ROUTES = [  # y, verb, title, lines, kind; "accept" points into the sandbox
    (116, "read", "The rest of your disk", ["read only"], "ok"),
    (202, "read", "The deny list", ["~/.ssh, keychains, browser data,", "other sandboxes, enclos's files"], "no"),
    (288, "reach", "Host services", ["Apple Events, launchd, preferences,", "pasteboard, other processes"], "no"),
    (374, "connect", "Egress proxy", ["on the host, outside the sandbox;", "logs every connection it decides on"], "ok"),
    (460, "connect", "Anywhere else", ["no direct connection, even to", "a host the proxy would allow"], "no"),
    (546, "accept", "Peers of its gateway", ["your Mac and its network, answered", "without the proxy or network log"], "ok"),
]
DESTINATIONS = [  # y, title, lines, kind
    (374, "Allowed", ["the public web, or", "only your allowlist"], "ok"),
    (460, "Refused", ["the host itself, cloud metadata,", "private hosts not opted in"], "no"),
]


class Canvas:
    def __init__(self, t: dict, w: int, h: int):
        self.t, self.w, self.h, self.out = t, w, h, []

    def text(self, x, y, s, size, color, weight="normal", anchor="middle"):
        self.out.append(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{color}" '
                        f'text-anchor="{anchor}">{escape(s)}</text>')

    def rect(self, x, y, w, h, stroke=None, fill=None):
        self.out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="11" fill="{fill or self.t["panel"]}" '
                        f'stroke="{stroke or self.t["line"]}" stroke-width="1.5"/>')

    def box(self, x, y, w, h, title, lines, kind="solid", fill=None, big=False):
        t = self.t
        stroke, width, dash, title_c, sub_c = t["line"], 1.5, "", t["text"], t["sub"]
        fill = fill or t["box"]
        if kind == "accent":
            stroke, width, fill = t["accent"], 2.5, t["accent_bg"]
        if kind == "later":
            dash, title_c, sub_c = ' stroke-dasharray="6 5"', t["later"], t["later"]
        if kind in ("ok", "no"):
            stroke, width, fill, sub_c = t[kind], 2, t[f"{kind}_bg"], t["text"]
        self.out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" fill="{fill}" '
                        f'stroke="{stroke}" stroke-width="{width}"{dash}/>')
        title_size, sub_size, step = (17, 14.5, 19) if big else (16, 13.5, 18)
        cx = x + w / 2
        top = y + h / 2 - (len(lines) * step) / 2 + 4
        self.text(cx, top, title, title_size, title_c, "600")
        for i, line in enumerate(lines):
            self.text(cx, top + step + 2 + i * step, line, sub_size, sub_c)

    def arrow(self, x1, y1, x2, y2):
        self.out.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{self.t["sub"]}" '
                        f'stroke-width="1.5" marker-end="url(#head)"/>')

    def route(self, points, kind):
        """A line that is allowed (`ok`), refused (`no`, dashed) or neither (`solid`)."""
        color = self.t["sub"] if kind == "solid" else self.t[kind]
        marker, dash = {"solid": ("head", ""), "ok": ("head-ok", ""), "no": ("head-no", ' stroke-dasharray="6 4"')}[kind]
        joined = " ".join(f"{x},{y}" for x, y in points)
        self.out.append(f'<polyline points="{joined}" fill="none" stroke="{color}" stroke-width="2"{dash} '
                        f'marker-end="url(#{marker})"/>')

    def svg(self, title: str, markers: dict) -> str:
        defs = "".join(f'<marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                       f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{color}"/></marker>'
                       for name, color in markers.items())
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" '
                f'height="{self.h}" font-family=\'{FONT}\' role="img" aria-labelledby="t">\n'
                f'<title id="t">{escape(title)}</title>\n<defs>{defs}</defs>\n' + "\n".join(self.out) + "\n</svg>\n")


def draw_architecture(t: dict) -> str:
    W, H = 1140, 640
    c = Canvas(t, W, H)
    c.out.append(f'<rect width="{W}" height="{H}" rx="12" fill="{t["bg"]}"/>')
    c.text(40, 38, TITLE, 18, t["text"], "600", "start")
    c.text(40, 62, SUBTITLE, 13.5, t["sub"], anchor="start")

    for x, title, lines, kind in CLIENTS:
        c.box(x, 84, 300, 80, title, lines, kind)
        c.arrow(x + 150, 164, x + 150, 190)

    c.rect(40, 192, 1060, 124)
    c.text(60, 216, "Core library", 15, t["text"], "600", "start")
    for x, title, lines in CORE:
        c.box(x, 228, 234, 68, title, lines)

    c.out.append(f'<polyline points="570,316 570,340" fill="none" stroke="{t["sub"]}" stroke-width="1.5"/>')
    c.out.append(f'<line x1="177" y1="340" x2="963" y2="340" stroke="{t["sub"]}" stroke-width="1.5"/>')
    for x, title, lines, kind in BACKENDS:
        c.arrow(x + 117, 340, x + 117, 358)
        c.box(x, 360, 234, 64, title, lines, kind)

    c.text(195, 455, "runs the runtime inside the sandbox", 13.5, t["sub"], anchor="start")

    c.rect(40, 476, 1060, 140)
    c.text(1080, 500, "Services: launchd on macOS, systemd on Linux", 15, t["text"], "600", "end")
    for i, (x, title, lines) in enumerate(SERVICES):
        c.box(x, 520, 300, 76, title, lines)
        if i:
            c.arrow(x - 60, 558, x - 2, 558)
    c.arrow(177, 424, 177, 518)  # last, so the panel does not cover its head

    return c.svg(TITLE, {"head": t["sub"]})


def draw_sandbox(t: dict) -> str:
    W, H = 1040, 664
    c = Canvas(t, W, H)
    c.out.append(f'<rect width="{W}" height="{H}" rx="12" fill="{t["bg"]}"/>')
    c.text(24, 36, SANDBOX_TITLE, 19, t["text"], "600", "start")
    c.text(24, 62, SANDBOX_SUBTITLE, 14.5, t["sub"], anchor="start")

    c.rect(24, 82, 714, 558)
    c.text(44, 106, "Your Mac", 15, t["text"], "600", "start")
    c.text(896, 106, "The network", 15, t["text"], "600")

    c.rect(44, 116, 340, 504, stroke=t["accent"], fill=t["accent_bg"])
    c.text(214, 146, "Sandbox lab", 18, t["text"], "600")
    c.text(214, 168, "Seatbelt applies its compiled policy", 14.5, t["sub"])
    for y, h, title, lines in INSIDE:
        c.box(60, y, 308, h, title, lines, big=True)

    for y, verb, title, lines, kind in ROUTES:
        mid = y + 37
        ends = [(384, mid), (449, mid)]
        c.route(ends[::-1] if verb == "accept" else ends, kind)
        c.text(416, mid - 9, verb, 13.5, t["sub"])
        if kind == "no":
            c.text(416, mid + 6, "×", 19, t["no"], "600")
        c.box(450, y, 270, 74, title, lines, kind, big=True)

    proxy_y, refused_y = ROUTES[3][0] + 37, DESTINATIONS[1][0] + 37
    c.route([(720, proxy_y - 12), (775, proxy_y - 12)], "ok")
    c.route([(720, proxy_y + 12), (756, proxy_y + 12), (756, refused_y), (775, refused_y)], "no")
    c.text(756, (proxy_y + refused_y) / 2 + 7, "×", 19, t["no"], "600")
    for y, title, lines, kind in DESTINATIONS:
        c.box(776, y, 240, 74, title, lines, kind, big=True)

    return c.svg(SANDBOX_TITLE, {"head": t["sub"], "head-ok": t["ok"], "head-no": t["no"]})


for name, theme in THEMES.items():
    (OUT / f"architecture-{name}.svg").write_text(draw_architecture(theme))
    (OUT / f"sandbox-{name}.svg").write_text(draw_sandbox(theme))
