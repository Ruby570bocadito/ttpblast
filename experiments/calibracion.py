#!/usr/bin/env python3
"""Experimento de calibración de los E-values de ttpblast.

Genera N conjuntos sintéticos con semillas distintas, busca en cada uno las
dos consultas de la demo y mide dos cosas:

1. Calibración: si los E-values están bien calibrados, un host benigno sale
   con E <= x con probabilidad x / H (H = hosts buscados). Benignos son los
   hosts sin ninguna cadena inyectada (36 de 40). Menos de lo esperado es
   conservador (menos falsas alarmas de las prometidas); más es optimista
   (peligroso).
2. Detección: E-value y puesto de cada cadena inyectada con su consulta.

La verdad se lee de truth.json, así que el experimento sigue valiendo si
cambian los escenarios.

Uso: python experiments/calibracion.py [--seeds 20] [--bin target/release/ttpblast]
     python experiments/calibracion.py --extra="--block 1"
Solo usa la biblioteca estándar.
"""

import argparse
import os
import json
import statistics
import subprocess
from pathlib import Path

# On Windows the binary needs its .exe to be found.
BIN = str(Path("target/release/ttpblast" + (".exe" if os.name == "nt" else "")))
QUERIES = ("phishing-lateral", "exfiltracion")


def search(binary, events, query, null_model, extra):
    out = subprocess.run(
        [binary, "search", "--query", f"queries/{query}.txt", "--events", events,
         "--null", null_model, "--evalue", "1e12", "--max-hits", "1000", "--no-baseline",
         "--json", *extra],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout
    result = json.loads(out)
    # Hosts with nothing resembling the query are not listed: their E is H.
    hits = [(hit["rank"], hit["host"], hit["evalue"]) for hit in result["hits"]]
    return hits, result["telemetry"]["hosts_with_symbols"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--bin", default=BIN)
    parser.add_argument("--work", default="data/calibracion")
    parser.add_argument("--extra", default="",
                        help='opciones extra para "ttpblast search", p. ej. --extra="--block 1"')
    args = parser.parse_args()
    extra = args.extra.split()

    models = ("cola", "gumbel")
    # expected: sum over searched benign hosts of P(E <= 1) = 1 / H if calibrated.
    benign = {m: {"n": 0, "expected": 0.0, "le1": 0, "le01": 0} for m in models}
    attack = {m: {} for m in models}
    hosts_searched = None
    for seed in range(1, args.seeds + 1):
        out_dir = Path(args.work) / f"semilla-{seed}"
        subprocess.run([args.bin, "synth", "--out", str(out_dir), "--seed", str(seed)],
                       check=True, capture_output=True)
        truth = json.loads((out_dir / "truth.json").read_text(encoding="utf-8"))
        attacked = {t["host"] for t in truth}
        for model in models:
            for query in QUERIES:
                chains = {t["host"]: t["escenario"] for t in truth if t["consulta"] == query}
                hits, hosts_searched = search(args.bin, str(out_dir / "events.ndjson"), query,
                                              model, extra)
                b = benign[model]
                b["n"] += hosts_searched - len(attacked)
                b["expected"] += (hosts_searched - len(attacked)) / hosts_searched
                for rank, host, evalue in hits:
                    if host in chains:
                        attack[model].setdefault(chains[host], []).append((evalue, rank))
                    elif host not in attacked:
                        b["le1"] += evalue <= 1
                        b["le01"] += evalue <= 0.1

    n = args.seeds
    print(f"{n} conjuntos sintéticos · {hosts_searched} hosts buscados en cada uno · consultas: "
          f"{', '.join(QUERIES)} · opciones: {args.extra or '(ninguna)'}\n")
    for model in models:
        b = benign[model]
        print(f"Modelo nulo: {model}")
        print(f"  benignos con E <= 1:   {b['le1']:>4}  (calibrado: ~{b['expected']:.1f}"
              f" en {b['n']} búsquedas de hosts benignos)")
        print(f"  benignos con E <= 0,1: {b['le01']:>4}  (calibrado: ~{b['expected'] / 10:.1f})")
        for name, values in attack[model].items():
            evalues = sorted(v[0] for v in values)
            ranks = [v[1] for v in values]
            found = sum(e <= 0.01 for e in evalues)
            print(f"  {name:<13} E mediana {statistics.median(evalues):.1e} · peor {evalues[-1]:.1e}"
                  f" · E <= 0,01 en {found}/{len(values)} · peor puesto {max(ranks)}")
        print()


if __name__ == "__main__":
    main()
