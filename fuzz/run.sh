#!/bin/bash
# Fuzzing of the decoders of snif with AFL++ (packages afl++ and clang).
#   ./fuzz/run.sh                  normal display, until Ctrl-C
#   ./fuzz/run.sh 3600             the same, for one hour
#   ./fuzz/run.sh -v               another display of snif, in fuzz/out-v
#   ./fuzz/run.sh --tcpdump 3600   the same with --tcpdump, for one hour
# The options are those of snif (-v, -1, --tcpdump, -x, "-T rtp"...). Several
# campaigns with different options can run at the same time, one by core.
# The crashes are in fuzz/out*/default/crashes/, to replay with:
#   fuzz/build/snif-fuzz -s -a <the options> -f fuzz/out-v/default/crashes/id:...
cd "$(dirname "$0")/.." || exit 1

T=(); OPTS=(); NAME=
for a in "$@"; do
  case "$a" in
    *[!0-9]*|'') OPTS+=("$a"); NAME="$NAME-$(echo "$a" | tr -d -- '-')" ;;
    *) T=(-V "$a") ;;
  esac
done
OUT=fuzz/out$NAME

mkdir -p fuzz/build fuzz/corpus
python3 fuzz/gen_corpus.py fuzz/corpus || exit 1

# one build shared by the campaigns: only when the sources changed
(
  flock 9
  if [ ! -x fuzz/build/snif-fuzz ] || [ -n "$(find . -maxdepth 1 \( -name '*.c' -o -name '*.h' \) -newer fuzz/build/snif-fuzz)" ]; then
    cp ./*.c ./*.h fuzz/build/
    rm -f fuzz/build/snif-fuzz.new
    (cd fuzz/build && AFL_USE_ASAN=1 afl-clang-fast -g -O1 -w -DHAVE_CONFIG_H -I. \
       -DPKGDATADIR='"/nonexistent"' ./*.c -o snif-fuzz.new -lpcap) || exit 1
    mv fuzz/build/snif-fuzz.new fuzz/build/snif-fuzz
  fi
) 9> fuzz/build/.lock || exit 1

export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
IN=fuzz/corpus
if [ -d "$OUT/default" ]; then # a previous run: go on with what it found
  IN=-
  for d in crashes hangs; do # the ones already seen are archived
    [ -n "$(ls "$OUT/default/$d" 2>/dev/null | grep -v README)" ] \
      && mv "$OUT/default/$d" "$OUT/default/$d.$(date +%Y%m%d-%H%M%S)"
  done
elif [ "$OUT" != fuzz/out ] && [ -d fuzz/out/default/queue ]; then
  # a new display: start from the packets found by the normal campaign too
  IN=$OUT.seeds
  rm -rf "$IN"; mkdir -p "$IN"
  cp fuzz/corpus/* "$IN"/
  n=0; for f in fuzz/out/default/queue/id:*; do n=$((n+1)); cp "$f" "$IN/q$n"; done
fi
# -s: no colors, -a: no tables to load (faster); the checksums are verified
exec afl-fuzz -i $IN -o "$OUT" -m none -t 2000 "${T[@]}" -- \
   fuzz/build/snif-fuzz -s -a "${OPTS[@]}" -f @@
