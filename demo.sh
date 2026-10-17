#!/usr/bin/env bash
# Demo completa: compila, genera telemetría sintética y busca la cadena de
# ejemplo. Los argumentos extra van a `ttpblast search` (p. ej. --null gumbel).
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release --quiet
./target/release/ttpblast synth --out data/demo
echo
./target/release/ttpblast search \
  --query queries/phishing-lateral.txt \
  --events data/demo/events.ndjson "$@"
