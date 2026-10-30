#!/usr/bin/env bash
# Demo guiada: compila y ejecuta `ttpblast demo`, que genera telemetría
# sintética, busca dos cadenas de ataque y se pone nota frente a la verdad.
# Los argumentos extra van a la demo (p. ej. ./demo.sh --null gumbel, o
# ./demo.sh --lang en).
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release --quiet
./target/release/ttpblast demo "$@"
