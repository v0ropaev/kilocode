#!/usr/bin/env python3
"""Render a recorded terminal session to PNG.

The input is the byte-for-byte output of `capture.sh`, escape codes and all. Nothing is rewritten:
the renderer only maps the colour codes Kilo emitted onto a light terminal palette and takes a
screenshot of the result, so what the image shows is what the terminal showed.

    render.py <name.ansi> <out.png> [line-ranges]

`line-ranges` is like "23-26,48-49": only those lines are drawn, and a "…" marks every gap, so a
cropped image still says out loud that something was left out. Line numbers match the `.txt`
transcript next to the `.ansi` file.
"""
import html
import os
import re
import subprocess
import sys
import tempfile

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

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
  html,body{{margin:0;background:#FAFAFC}}
  .term{{background:#FFFFFF;border:1px solid #E4E4EA;border-radius:10px;
        padding:22px 26px;margin:18px;font:14px/1.55 "SF Mono","Menlo",monospace;
        color:#1A1A1F;white-space:pre-wrap;word-break:break-all}}
</style><div class="term">{body}</div>"""


def main() -> int:
    src, dst = sys.argv[1], sys.argv[2]
    text = open(src, encoding="utf-8", errors="replace").read()
    lines = text.split("\n")
    if len(sys.argv) > 3:
        picked, last = [], None
        for chunk in sys.argv[3].split(","):
            first, _, end = chunk.partition("-")
            lo, hi = int(first), int(end or first)
            if last is not None and lo > last + 1:
                picked.append("…")
            picked.extend(lines[lo - 1 : hi])
            last = hi
        lines = picked
    text = "\n".join(lines).strip("\n")
    page = PAGE.format(body=to_html(text))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "page.html")
        open(path, "w", encoding="utf-8").write(page)
        # Width is fixed; height follows the wrapped line count so nothing is cut off.
        rows = text.count("\n") + 1
        wrapped = sum(1 + len(line) // 118 for line in text.split("\n"))
        height = int(wrapped * 21.7 + 80)
        subprocess.run(
            [CHROME, "--headless", "--disable-gpu", "--no-sandbox",
             f"--window-size=1180,{height}", "--force-device-scale-factor=2",
             "--virtual-time-budget=1500", f"--screenshot={dst}", f"file://{path}"],
            capture_output=True, timeout=180,
        )
    print(f"{dst}: {rows} lines, {os.path.getsize(dst)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
