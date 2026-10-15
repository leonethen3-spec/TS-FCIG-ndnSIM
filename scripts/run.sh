#!/usr/bin/env bash
# Run one topology with matched traffic and the selected router decision rule.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  echo 'Usage: bash scripts/run.sh [small|large] [normal|cifa|tsfcig|pet-only|acf-only|basic|all] [run] [base|period6|rate100] [formal|short] [label]'
}
if [[ "${1:-}" == --help ]]; then usage; exit 0; fi
[[ $# -le 6 ]] || { usage >&2; exit 2; }
topology="${1:-small}"
selection="${2:-tsfcig}"
run="${3:-1}"
attack="${4:-base}"
profile="${5:-formal}"
label="${6:-paper}"
[[ "$topology" =~ ^(small|large)$ ]] || { usage >&2; exit 2; }
[[ "$run" =~ ^[1-9][0-9]*$ && "$label" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Invalid run number or label' >&2; exit 2; }
case "$attack" in
  base) period=4; rest=1; rate=50 ;;
  period6) period=6; rest=2; rate=50 ;;
  rate100) period=4; rest=1; rate=100 ;;
  *) usage >&2; exit 2 ;;
esac
case "$profile" in
  formal) duration=100; start=40; stop=80 ;;
  short) duration=20; start=2; stop=14 ;;
  *) usage >&2; exit 2 ;;
esac
case "$selection" in
  basic) modes=(normal cifa tsfcig) ;;
  all) modes=(normal cifa tsfcig pet-only acf-only) ;;
  normal|cifa|tsfcig|pet-only|acf-only) modes=("$selection") ;;
  *) usage >&2; exit 2 ;;
esac

directory="results/${label}-${topology}-${attack}-${profile}-r${run}"
# Check all requested cases before starting any run, including partially written outputs.
for mode in "${modes[@]}"; do
  if compgen -G "$directory/$mode-*" > /dev/null; then
    echo "Output already exists: $directory/$mode. Choose a different label." >&2
    exit 2
  fi
done
mkdir -p "$directory"
python2 ./waf --targets="tsfcig-${topology}" 2>&1 | tee "$directory/build.log"
for mode in "${modes[@]}"; do
  prefix="$directory/$mode"
  args=(--mode="$mode" --output="$prefix" --seed=10 --run="$run"
        --duration="$duration" --drain=8 --attackStart="$start" --attackStop="$stop"
        --attackPeriod="$period" --restInterval="$rest" --attackRate="$rate"
        --legitimateRate=50 --producerDelay=1.6 --randomize=exponential)
  printf '%q ' "./build/tsfcig-${topology}" "${args[@]}" > "$prefix-command.txt"
  printf '\n' >> "$prefix-command.txt"
  "./build/tsfcig-${topology}" "${args[@]}" 2>&1 | tee "$prefix-run.log"
  [[ -s "$prefix-completed.txt" ]] || { echo "Missing completion record: $prefix" >&2; exit 1; }
done
