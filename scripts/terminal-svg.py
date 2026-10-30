#!/usr/bin/env python3
"""Convierte salida de terminal con colores ANSI en una imagen SVG.

Sirve para las imágenes del README: la salida real de ttpblast, con sus
colores, sin capturas de pantalla. Solo entiende los códigos que usa
ttpblast (negrita, atenuado y los colores básicos).

Uso:
  ttpblast search ... --color always > salida.txt
  python scripts/terminal-svg.py salida.txt docs/terminal.svg --title "ttpblast search"
Solo usa la biblioteca estándar.
"""

import argparse
import html
import re

FG = "#c9d1d9"
COLORS = {"31": "#ff7b72", "32": "#7ee787", "33": "#e3b341", "36": "#5fd4c7"}
SGR = re.compile(r"\x1b\[([0-9;]*)m")
CHAR_W, LINE_H, FONT = 8.4, 19, 14
PAD_X, PAD_TOP, PAD_BOTTOM = 22, 50, 18


def spans(line):
    """(text, bold, dim, color) runs of one line."""
    bold = dim = False
    color = None
    pos = 0
    for match in SGR.finditer(line):
        if match.start() > pos:
            yield line[pos:match.start()], bold, dim, color
        for code in (match.group(1) or "0").split(";"):
            if code in ("", "0"):
                bold = dim = False
                color = None
            elif code == "1":
                bold = True
            elif code == "2":
                dim = True
            elif code in COLORS:
                color = COLORS[code]
        pos = match.end()
    if pos < len(line):
        yield line[pos:], bold, dim, color


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--title", default="ttpblast")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as f:
        lines = f.read().rstrip("\n").split("\n")
    columns = max(len(SGR.sub("", line)) for line in lines)
    width = round(PAD_X * 2 + columns * CHAR_W)
    height = PAD_TOP + len(lines) * LINE_H + PAD_BOTTOM

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(args.title)}">',
        '<style>text{font-family:"Cascadia Mono","SF Mono",Menlo,Consolas,"DejaVu Sans Mono",'
        f'"Liberation Mono",monospace;font-size:{FONT}px;white-space:pre}}</style>',
        f'<rect width="{width}" height="{height}" rx="10" fill="#0d1117"/>',
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="10" fill="none" stroke="#30363d"/>',
        '<circle cx="22" cy="20" r="6" fill="#ff5f57"/><circle cx="42" cy="20" r="6" fill="#febc2e"/>'
        '<circle cx="62" cy="20" r="6" fill="#28c840"/>',
        f'<text x="{width / 2}" y="25" text-anchor="middle" fill="#8b949e" '
        f'style="font-size:12px">{html.escape(args.title)}</text>',
    ]
    for i, line in enumerate(lines):
        y = PAD_TOP + (i + 1) * LINE_H - 5
        parts = []
        for text, bold, dim, color in spans(line):
            attrs = [f'fill="{color or FG}"']
            if bold:
                attrs.append('font-weight="bold"')
            if dim:
                attrs.append('opacity="0.55"')
            parts.append(f'<tspan {" ".join(attrs)}>{html.escape(text)}</tspan>')
        if parts:
            out.append(f'<text x="{PAD_X}" y="{y}" xml:space="preserve">{"".join(parts)}</text>')
    out.append("</svg>")
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
