"""Draws docs/diagrams/architecture-{light,dark}.svg.

Run from the repository root: uv run --no-project python docs/diagrams/architecture.py
Edit the boxes below, then run it again; both themes always match.
"""

from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).parent
W, H = 1140, 640
FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif'

THEMES = {
    "dark": dict(bg="#0d1117", panel="#161b22", box="#0d1117", line="#3d444d", text="#e6edf3",
                 sub="#9198a1", later="#6e7681", accent="#4493f8", accent_bg="#121d2f"),
    "light": dict(bg="#ffffff", panel="#f6f8fa", box="#ffffff", line="#d1d9e0", text="#1f2328",
                  sub="#59636e", later="#818b98", accent="#0969da", accent_bg="#ddf4ff"),
}

TITLE = "Every client goes through one core; each sandbox runs as its own services"
SUBTITLE = "No daemon: the CLI writes state and audit, and launchd keeps each sandbox's proxy and gateway running"

CLIENTS = [  # x, title, lines, kind
    (40, "enclos (CLI)", ["every operation", "milestone 1"], "accent"),
    (420, "enclos ui", ["local web UI", "same audit log; later"], "later"),
    (800, "enclos mcp", ["for scripts and operator agents", "later"], "later"),
]
CORE = [
    (60, "State + audit", ["SQLite + JSONL"]),
    (322, "Policy", ["layers, snapshots, compiled"]),
    (584, "Runtime adapters", ["install, login, agents"]),
    (846, "Backend API", ["one implementation each"]),
]
BACKENDS = [
    (60, "Seatbelt", ["macOS, milestone 1"], "solid"),
    (322, "bubblewrap", ["Linux, later"], "later"),
    (584, "OpenShell", ["later"], "later"),
    (846, "MicroVM", ["later: libkrun"], "later"),
]
SERVICES = [
    (60, "Sandbox lab", ["Hermes and its agents", "its own home and policy"]),
    (420, "Egress proxy", ["one per sandbox, on the host", "logs every connection"]),
    (780, "Allowed domains", ["at validated addresses", "everything else refused"]),
]


def draw(t: dict) -> str:
    out = []

    def text(x, y, s, size, color, weight="normal", anchor="middle"):
        out.append(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{color}" '
                   f'text-anchor="{anchor}">{escape(s)}</text>')

    def box(x, y, w, h, title, lines, kind="solid", fill=None):
        stroke, width, dash, title_c, sub_c = t["line"], 1.5, "", t["text"], t["sub"]
        fill = fill or t["box"]
        if kind == "accent":
            stroke, width, fill = t["accent"], 2.5, t["accent_bg"]
        if kind == "later":
            dash, title_c, sub_c = ' stroke-dasharray="6 5"', t["later"], t["later"]
        out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" fill="{fill}" '
                   f'stroke="{stroke}" stroke-width="{width}"{dash}/>')
        cx = x + w / 2
        top = y + h / 2 - (len(lines) * 18) / 2 + 4
        text(cx, top, title, 16, title_c, "600")
        for i, line in enumerate(lines):
            text(cx, top + 20 + i * 18, line, 13.5, sub_c)

    def arrow(x1, y1, x2, y2):
        out.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{t["sub"]}" '
                   f'stroke-width="1.5" marker-end="url(#head)"/>')

    out.append(f'<rect width="{W}" height="{H}" rx="12" fill="{t["bg"]}"/>')
    text(40, 38, TITLE, 18, t["text"], "600", "start")
    text(40, 62, SUBTITLE, 13.5, t["sub"], anchor="start")

    for x, title, lines, kind in CLIENTS:
        box(x, 84, 300, 80, title, lines, kind)
        arrow(x + 150, 164, x + 150, 190)

    out.append(f'<rect x="40" y="192" width="1060" height="124" rx="11" fill="{t["panel"]}" stroke="{t["line"]}" stroke-width="1.5"/>')
    text(60, 216, "Core library", 15, t["text"], "600", "start")
    for x, title, lines in CORE:
        box(x, 228, 234, 68, title, lines)

    out.append(f'<polyline points="570,316 570,340" fill="none" stroke="{t["sub"]}" stroke-width="1.5"/>')
    out.append(f'<line x1="177" y1="340" x2="963" y2="340" stroke="{t["sub"]}" stroke-width="1.5"/>')
    for x, title, lines, kind in BACKENDS:
        arrow(x + 117, 340, x + 117, 358)
        box(x, 360, 234, 64, title, lines, kind)

    text(195, 455, "runs the runtime inside the sandbox", 13.5, t["sub"], anchor="start")

    out.append(f'<rect x="40" y="476" width="1060" height="140" rx="11" fill="{t["panel"]}" stroke="{t["line"]}" stroke-width="1.5"/>')
    text(1080, 500, "Services: launchd on macOS (systemd on Linux, later)", 15, t["text"], "600", "end")
    for i, (x, title, lines) in enumerate(SERVICES):
        box(x, 520, 300, 76, title, lines)
        if i:
            arrow(x - 60, 558, x - 2, 558)
    arrow(177, 424, 177, 518)  # last, so the panel does not cover its head

    head = (f'<defs><marker id="head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
            f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{t["sub"]}"/></marker></defs>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
            f'font-family=\'{FONT}\' role="img" aria-labelledby="t">\n<title id="t">{escape(TITLE)}</title>\n'
            + head + "\n" + "\n".join(out) + "\n</svg>\n")


for name, theme in THEMES.items():
    (OUT / f"architecture-{name}.svg").write_text(draw(theme))
