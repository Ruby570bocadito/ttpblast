#!/usr/bin/env python3
"""Experimento de calibración de los E-values de ttpblast.

Genera N conjuntos sintéticos con semillas distintas, busca la cadena de la
demo en cada uno y mide dos cosas:

1. Calibración: si los E-values están bien calibrados, un host benigno sale
   con E <= x con probabilidad x / H (H = hosts buscados). Con 37 hosts
   benignos por conjunto, se esperan ~0,93 hosts benignos con E <= 1 por
   conjunto. Menos es conservador (menos falsas alarmas de las prometidas);
   más es optimista (peligroso).
2. Detección: E-value y puesto de los tres escenarios inyectados.

Uso: python3 experiments/calibracion.py [--seeds 10] [--bin target/release/ttpblast]
Solo usa la biblioteca estándar.
"""

import argparse
import json
import subprocess
from pathlib import Path

ATTACK_HOSTS = {"ws-legal-02": "exacta", "ws-finance-04": "variante", "ws-sales-03": "parcial"}


def search(binary, events, query, null_model, extra):
    out = subprocess.run(
        [binary, "search", "--query", query, "--events", events, "--null", null_model,
         "--evalue", "1e12", "--max-hits", "1000", "--no-baseline", "--json", *extra],
        check=True, capture_output=True, text=True,
    ).stdout
    for hit in json.loads(out)["hits"]:
        yield hit["rank"], hit["host"], hit["evalue"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--bin", default="target/release/ttpblast")
    parser.add_argument("--query", default="queries/phishing-lateral.txt")
    parser.add_argument("--work", default="data/calibracion")
    parser.add_argument("--extra", default="",
                        help='opciones extra para "ttpblast search", p. ej. --extra="--block 1"')
    args = parser.parse_args()
    extra = args.extra.split()

    models = ("cola", "gumbel")
    stats = {m: {"benign": 0, "le1": 0, "le01": 0, "attack": {}} for m in models}
    for seed in range(1, args.seeds + 1):
        out_dir = Path(args.work) / f"semilla-{seed}"
        subprocess.run([args.bin, "synth", "--out", str(out_dir), "--seed", str(seed)],
                       check=True, capture_output=True)
        for model in models:
            s = stats[model]
            for rank, host, evalue in search(args.bin, str(out_dir / "events.ndjson"), args.query, model, extra):
                if host in ATTACK_HOSTS:
                    s["attack"].setdefault(ATTACK_HOSTS[host], []).append((evalue, rank))
                else:
                    s["benign"] += 1
                    s["le1"] += evalue <= 1
                    s["le01"] += evalue <= 0.1

    n = args.seeds
    print(f"{n} conjuntos sintéticos · 40 hosts cada uno (37 benignos) · opciones: {args.extra or '(ninguna)'}\n")
    for model in models:
        s = stats[model]
        print(f"Modelo nulo: {model}")
        print(f"  hosts benignos con E <= 1:   {s['le1']:>3}  (calibrado: ~{n * 37 / 40:.1f})")
        print(f"  hosts benignos con E <= 0,1: {s['le01']:>3}  (calibrado: ~{n * 37 / 400:.1f})")
        for name in ("exacta", "variante", "parcial"):
            values = sorted(s["attack"].get(name, []))
            if not values:
                print(f"  {name:<9} no encontrada")
                continue
            evalues = [v[0] for v in values]
            ranks = [v[1] for v in values]
            print(f"  {name:<9} E mediana {evalues[len(evalues) // 2]:.1e} · peor {evalues[-1]:.1e}"
                  f" · encontrada {len(values)}/{n} · peor puesto {max(ranks)}")
        print()


if __name__ == "__main__":
    main()
