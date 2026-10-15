#!/usr/bin/env bash
# Table 4 baseline, Table 5 single-feature alternatives, and Table 6 traffic settings.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${1:-}" == --help ]]; then
  echo 'Usage: bash scripts/run-paper.sh [small|large|both] [label]'
  exit 0
fi
[[ $# -le 2 ]] || { echo 'Expected topology and optional label' >&2; exit 2; }
selection="${1:-both}"
label="${2:-paper}"
[[ "$label" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Invalid label' >&2; exit 2; }
case "$selection" in
  both) topologies=(small large) ;;
  small|large) topologies=("$selection") ;;
  *) echo 'Topology must be small, large or both' >&2; exit 2 ;;
esac
# Reject an occupied campaign before launching the first case.
for topology in "${topologies[@]}"; do
  for attack in base period6 rate100; do
    for run in {1..10}; do
      directory="results/${label}-${topology}-${attack}-formal-r${run}"
      [[ ! -e "$directory" ]] || { echo "Output exists: $directory" >&2; exit 2; }
    done
  done
done
for topology in "${topologies[@]}"; do
  for run in {1..10}; do
    bash scripts/run.sh "$topology" all "$run" base formal "$label"
    bash scripts/run.sh "$topology" basic "$run" period6 formal "$label"
    bash scripts/run.sh "$topology" basic "$run" rate100 formal "$label"
  done
done
