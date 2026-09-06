#!/usr/bin/env python3
"""Render a recorded terminal session to PNG.

The input is the byte-for-byte output of `capture.sh`, escape codes and all. Nothing is rewritten:
the renderer only maps the colour codes Kilo emitted onto a light terminal palette and takes a
screenshot of the result, so what the image shows is what the terminal showed.

    render.py <name.ansi> <out.png> [line-ranges] [--width PX] [--font PX]

`line-ranges` is like "23-26,48-49": only those lines are drawn, and a "…" marks every gap, so a
cropped image still says out loud that something was left out. Line numbers match the `.txt`
transcript next to the `.ansi` file.

`--width` and `--font` exist for one reason: a slide has a font floor, and a terminal screenshot
has to clear it. Placed across a 10-inch slide, the default 14 px type in a 1180 px window lands at
about 7 pt — unreadable from the back of a room, whatever it is cropped to. The type on the slide
scales as `font / width`, so a *narrower* render with *larger* type is the only way up: 30 px in an
860 px window reaches 22.5 pt at full slide width. It costs characters per line, which is why the
pitch renders show two transcript lines and not twenty.
"""
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile

def _chrome() -> str:
    """The headless browser that takes the screenshot.

    Any Chromium build renders this page identically — it is one div of monospace text — so the
    first one found is used. CHROME_BIN overrides the search when several are installed.
    """
    override = os.environ.get("CHROME_BIN")
    candidates = [override] if override else []
    candidates += [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
        "brave-browser", "microsoft-edge",
    ]
    for name in candidates:
        found = name if os.path.isfile(name) else shutil.which(name)
        if found:
            return found
    raise SystemExit(
        "render.py: no Chromium-based browser found. Install one, or set CHROME_BIN=/path/to/chrome."
    )


CHROME = None  # resolved on first use by main()

# A light terminal palette. Same escape codes, readable on a projector.
COLORS = {
    "31": "#B3261E", "91": "#B3261E",   # red
    "32": "#1B6E3C", "92": "#1B6E3C",   # green
    "33": "#8A5A00", "93": "#8A5A00",   # yellow
    "34": "#0000FF", "94": "#0000FF",   # blue
    "35": "#8843FF", "95": "#8843FF",   # magenta
    "36": "#0F6C7A", "96": "#0F6C7A",   # cyan
    "90": "#8A8A93", "37": "#3C3C43",
}

TOKEN = re.compile(r"\x1b\[([0-9;]*)m")


def to_html(text: str) -> str:
    # TOKEN.split keeps the escape parameters and the text between them alternating.
    out, open_spans = [], 0
    parts = TOKEN.split(text)
    out.append(html.escape(parts[0]))
    for i in range(1, len(parts), 2):
        codes = [c for c in parts[i].split(";") if c != ""] or ["0"]
        body = html.escape(parts[i + 1]) if i + 1 < len(parts) else ""
        style = []
        reset = False
        for code in codes:
            if code == "0":
                reset = True
            elif code == "1":
                style.append("font-weight:700")
            elif code == "2":
                style.append("color:#8A8A93")
            elif code in COLORS:
                style.append(f"color:{COLORS[code]}")
        if reset:
            out.append("</span>" * open_spans)
            open_spans = 0
        if style:
            out.append(f"<span style=\"{';'.join(style)}\">")
            open_spans += 1
        out.append(body)
    out.append("</span>" * open_spans)
    return "".join(out)


PAGE = """<!doctype html><meta charset="utf-8"><style>
  html,body{{margin:0;background:#FAFAFC;overflow:hidden}}
  .term{{background:#FFFFFF;border:1px solid #E4E4EA;border-radius:10px;
        padding:{pad}px {pad}px;margin:{margin}px;font:{font}px/1.55 "SF Mono","Menlo",monospace;
        color:#1A1A1F;white-space:pre-wrap;word-break:break-all}}
</style><div class="term">{body}</div>"""


def option(name, fallback):
    if name in sys.argv:
        return int(sys.argv[sys.argv.index(name) + 1])
    return fallback


def main() -> int:
    global CHROME
    CHROME = _chrome()
    src, dst = sys.argv[1], sys.argv[2]
    ranges = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else None
    width = option("--width", 1180)
    font = option("--font", 14)
    # A big-type render needs its chrome to shrink with it, or the padding eats the height budget.
    pad, margin = (14, 10) if font > 20 else (22, 18)

    text = open(src, encoding="utf-8", errors="replace").read()
    lines = text.split("\n")
    if ranges:
        picked, last = [], None
        for chunk in ranges.split(","):
            first, _, end = chunk.partition("-")
            lo, hi = int(first), int(end or first)
            if last is not None and lo > last + 1:
                picked.append("…")
            picked.extend(lines[lo - 1 : hi])
            last = hi
        lines = picked
    text = "\n".join(lines).strip("\n")
    page = PAGE.format(body=to_html(text), font=font, pad=pad, margin=margin)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "page.html")
        open(path, "w", encoding="utf-8").write(page)
        # Width is fixed; height follows the wrapped line count so nothing is cut off. SF Mono
        # advances about 0.6 em, so the columns that fit follow from the width and the type size.
        rows = text.count("\n") + 1
        columns = max(int((width - 2 * margin - 2 * pad - 2) / (font * 0.6)), 8)
        wrapped = sum(1 + len(line) // columns for line in text.split("\n"))
        height = int(wrapped * font * 1.55 + 2 * pad + 2 * margin + 4)
        done = subprocess.run(
            [CHROME, "--headless", "--disable-gpu", "--no-sandbox",
             f"--window-size={width},{height}", "--force-device-scale-factor=2",
             "--virtual-time-budget=1500", f"--screenshot={dst}", f"file://{path}"],
            capture_output=True, timeout=180,
        )
        # Chrome exits 0 when it cannot render, so the file's absence is the only honest signal.
        if not os.path.exists(dst):
            sys.stderr.write(done.stderr.decode("utf-8", "replace")[-2000:] + "\n")
            raise SystemExit(f"render.py: {CHROME} produced no screenshot for {dst}")
    print(f"{dst}: {rows} lines, {columns} columns, {os.path.getsize(dst)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
