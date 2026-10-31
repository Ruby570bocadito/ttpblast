#!/usr/bin/env python3
"""Anima la salida de ttpblast en un GIF para el README.

Cuenta la misma historia que ve un analista: primero el progreso en vivo
—el spinner y los barajados contándose, la señal separándose del ruido—, y
luego la tabla de resultados y el alineamiento de la variante emergiendo
línea a línea. Movimiento, no una captura.

Toma la salida real de `ttpblast search ... --color always` (los mismos
códigos ANSI que entiende scripts/terminal-svg.py) y la convierte en un GIF
en bucle. Solo usa Pillow y las fuentes DejaVu del sistema.

Uso:
  ttpblast search --query queries/phishing-lateral.txt \\
      --events data/demo/events.ndjson --details 2 --color always > salida.txt
  python scripts/demo-gif.py salida.txt docs/demo.gif --hosts 40 --shuffles 200
"""

import argparse
import re

from PIL import Image, ImageDraw, ImageFont

FG = (201, 209, 219)
BG = (13, 17, 23)
COLORS = {
    "31": (255, 123, 114),  # alert / far from chance
    "32": (126, 231, 135),  # identical
    "33": (227, 179, 65),   # similar
    "36": (95, 212, 199),   # brand / query (teal)
}
SGR = re.compile(r"\x1b\[([0-9;]*)m")
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_SIZE = 26
PAD_X, PAD_TOP, PAD_BOTTOM = 30, 56, 22
SPINNER = "▏▎▍▌▋▊▉█▉▊▋▌▍▎"


def spans(line):
    """(text, bold, dim, color) runs of one line, reading ttpblast's SGR codes."""
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


def thousands(n):
    """Spanish thousands separator, matching the CLI's i18n::count."""
    return f"{n:,}".replace(",", ".")


def blend(color, t):
    """`color` mixed toward the background by 1-t (t=1 full colour, t=0 gone)."""
    return tuple(round(bg + (c - bg) * t) for c, bg in zip(color, BG))


class Canvas:
    """A fixed-size terminal frame: dark panel, rounded, with a title bar."""

    def __init__(self, cols, rows, title):
        self.font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
        self.char_w = self.font.getlength("M")
        self.line_h = round(FONT_SIZE * 1.42)
        self.title = title
        self.rows = rows
        self.width = round(PAD_X * 2 + cols * self.char_w)
        self.height = PAD_TOP + rows * self.line_h + PAD_BOTTOM

    def frame(self, lines, dim_all=1.0):
        img = Image.new("RGB", (self.width, self.height), BG)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([0, 0, self.width - 1, self.height - 1], radius=12,
                            outline=(48, 54, 61), width=1)
        for cx, col in ((PAD_X, (255, 95, 87)), (PAD_X + 20, (254, 188, 46)),
                        (PAD_X + 40, (40, 200, 64))):
            d.ellipse([cx - 6, 14, cx + 6, 26], fill=col)
        d.text((self.width / 2, 20), self.title, font=self.font, fill=(139, 148, 158),
               anchor="mm")
        for i, line in enumerate(lines):
            y = PAD_TOP + i * self.line_h
            x = PAD_X
            for text, bold, dim, color in spans(line):
                fill = color or FG
                if dim:
                    fill = blend(fill, 0.55)
                if dim_all < 1.0:
                    fill = blend(fill, dim_all)
                d.text((x, y), text, font=self.font, fill=fill,
                       stroke_width=1 if bold else 0, stroke_fill=fill)
                x += self.char_w * len(text)
        return img


def plain(line):
    return SGR.sub("", line)


def build(src, title, hosts, shuffles, lang):
    word = "shuffles" if lang == "en" else "barajados"
    lines = src.rstrip("\n").split("\n")
    cols = max(len(plain(l)) for l in lines)
    # The spinner line can be wider than the output; keep the canvas steady.
    sample = f"\x1b[1;36m█\x1b[0m \x1b[2m{hosts}/{hosts} hosts · {thousands(hosts * shuffles)} {word}\x1b[0m"
    cols = max(cols, len(plain(sample)))
    canvas = Canvas(cols, len(lines), title)

    frames, durations = [], []

    # Phase 1: the live counter climbing — the shuffles being counted, the
    # signal pulled out of the noise. One frame per spinner tick.
    done = [5, 12, 20, 28, 35, 40, 40]
    for i, n in enumerate(done):
        n = min(n, hosts)
        shuf = thousands(round(n / hosts * hosts * shuffles))
        spin = SPINNER[i % len(SPINNER)]
        line = f"\x1b[1;36m{spin}\x1b[0m \x1b[2m{n}/{hosts} hosts · {shuf} {word}\x1b[0m"
        frames.append(canvas.frame([line]))
        durations.append(110)

    # Phase 2: the results emerge, a few lines at a time.
    step = 2
    for upto in range(step, len(lines) + 1, step):
        frames.append(canvas.frame(lines[:upto]))
        durations.append(150)

    # Phase 3: hold the full screen, then loop.
    frames.append(canvas.frame(lines))
    durations.append(2600)

    return frames, durations


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--title", default="ttpblast demo")
    p.add_argument("--hosts", type=int, default=40)
    p.add_argument("--shuffles", type=int, default=200)
    p.add_argument("--lang", choices=("es", "en"), default="es")
    args = p.parse_args()

    with open(args.input, encoding="utf-8") as f:
        src = f.read()
    frames, durations = build(src, args.title, args.hosts, args.shuffles, args.lang)
    frames[0].save(args.output, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, disposal=2, optimize=True)
    print(f"{args.output}: {len(frames)} frames, {frames[0].width}x{frames[0].height}")


if __name__ == "__main__":
    main()
