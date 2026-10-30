#!/usr/bin/env python3
"""Experimento de evasión: ¿cuánto relleno hace falta para esconder una cadena?

Un atacante que conozca ttpblast puede intercalar comandos corrientes (cmd,
schtasks, ipconfig...) entre los pasos de su cadena: cada uno abre un hueco en
el alineamiento y le resta puntos. Este experimento genera la telemetría de
la demo con 0, 1, 2... comandos de relleno entre cada dos pasos de cada
cadena (`ttpblast synth --padding N`) y mide, para varios costes de hueco:

- detección: cuántas cadenas inyectadas siguen con E <= 0,01, y su E mediano;
- falsas alarmas: hosts benignos con E <= 1 (calibrado: ~1 de cada 40).

Los costes se dan como faltan/de-más: "4/1" cobra lo mismo por un paso que
falta que por uno de más (abrir 4, cada otro 1); "4/1:1/0" sigue cobrando 4/1
por los que faltan, pero solo 1 por cada racha de pasos de más, sea cual sea
su longitud. Los E-values siguen calibrados con cualquier coste, porque los
barajados usan los mismos; lo que cambia es qué parecidos puntúan alto.

Uso: python experiments/evasion.py [--seeds 10] [--padding 0,1,2,3,4]
     [--gaps 4/1,2/0,4/1:1/0] [--bin target/release/ttpblast]
Solo usa la biblioteca estándar.
"""

import argparse
import json
import os
import statistics
import subprocess
from pathlib import Path

# On Windows the binary needs its .exe to be found.
BIN = str(Path("target/release/ttpblast" + (".exe" if os.name == "nt" else "")))
QUERIES = ("phishing-lateral", "exfiltracion")


def parse_gaps(spec):
    """"4/1" -> ((4, 1), (4, 1)); "4/1:1/0" -> ((4, 1), (1, 0))."""
    missing, _, extra = spec.partition(":")
    pair = lambda text: tuple(int(x) for x in text.split("/"))
    return pair(missing), pair(extra or missing)


def search(binary, events, query, gaps):
    (gap_open, gap_extend), (extra_open, extra_extend) = gaps
    out = subprocess.run(
        [binary, "search", "--query", f"queries/{query}.txt", "--events", events,
         "--evalue", "1e12", "--max-hits", "1000", "--no-baseline", "--json",
         "--gap-open", str(gap_open), "--gap-extend", str(gap_extend),
         "--extra-open", str(extra_open), "--extra-extend", str(extra_extend)],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout
    return {hit["host"]: hit["evalue"] for hit in json.loads(out)["hits"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--padding", default="0,1,2,3,4")
    parser.add_argument("--gaps", default="4/1,2/0,4/1:2/0,4/1:1/0",
                        help="costes a probar, faltan/de-más (los de ttpblast: 4/1:1/0)")
    parser.add_argument("--bin", default=BIN)
    parser.add_argument("--work", default="data/evasion")
    args = parser.parse_args()
    paddings = [int(p) for p in args.padding.split(",")]
    specs = args.gaps.split(",")

    results = {}
    for padding in paddings:
        for seed in range(1, args.seeds + 1):
            out_dir = Path(args.work) / f"relleno-{padding}" / f"semilla-{seed}"
            subprocess.run([args.bin, "synth", "--out", str(out_dir), "--seed", str(seed),
                            "--padding", str(padding)], check=True, capture_output=True)
            truth = json.loads((out_dir / "truth.json").read_text(encoding="utf-8"))
            attacked = {t["host"] for t in truth}
            for spec in specs:
                r = results.setdefault((padding, spec), {"found": 0, "chains": 0, "evalues": {},
                                                         "fp": 0, "benign": 0})
                for query in QUERIES:
                    evalues = search(args.bin, str(out_dir / "events.ndjson"), query, parse_gaps(spec))
                    for t in truth:
                        if t["consulta"] != query:
                            continue
                        e = evalues.get(t["host"], float("inf"))
                        r["chains"] += 1
                        r["found"] += e <= 0.01
                        r["evalues"].setdefault(t["escenario"], []).append(e)
                    for host, e in evalues.items():
                        if host not in attacked:
                            r["benign"] += 1
                            r["fp"] += e <= 1

    scenarios = sorted({s for r in results.values() for s in r["evalues"]})
    print(f"{args.seeds} semillas por fila · consultas: {', '.join(QUERIES)}")
    print("Por fila: cadenas con E <= 0,01 / total · E mediano de cada escenario · "
          "benignos con E <= 1 por cada 40 búsquedas (calibrado: ~1)\n")
    for spec in specs:
        (go, ge), (eo, ee) = parse_gaps(spec)
        print(f"Faltan -{go}/-{ge} · de más -{eo}/-{ee}")
        print(f"  {'relleno':>7}  {'detectadas':>10}  " + "  ".join(f"{s:>12}" for s in scenarios)
              + "  falsas/40")
        for padding in paddings:
            r = results[(padding, spec)]
            medians = "  ".join(f"{statistics.median(r['evalues'][s]):>12.1e}" for s in scenarios)
            fp = 40 * r["fp"] / max(r["benign"], 1)
            print(f"  {padding:>7}  {r['found']:>4}/{r['chains']:<5}  {medians}  {fp:>8.2f}")
        print()


if __name__ == "__main__":
    main()
