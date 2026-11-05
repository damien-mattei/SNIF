#!/bin/bash
# Fuzzing of the decoders of snif with AFL++ (packages afl++ and clang).
#   ./fuzz/run.sh                  normal display, until Ctrl-C
#   ./fuzz/run.sh 3600             the same, for one hour
#   ./fuzz/run.sh -v               another display of snif, in out-v
#   ./fuzz/run.sh --tcpdump 3600   the same with --tcpdump, for one hour
# The options are those of snif (-v, -1, --tcpdump, -x, "-T rtp"...). Several
# campaigns with different options can run at the same time, one by core.
# Everything is written in ~/snif-fuzz (or $SNIF_FUZZ_DIR), out of the source
# directory: a campaign creates thousands of files, not to be synchronized.
# The crashes are in ~/snif-fuzz/out*/default/crashes/, to replay with:
#   ~/snif-fuzz/build/snif-fuzz -s -a <the options> -f ~/snif-fuzz/out-v/default/crashes/id:...
cd "$(dirname "$0")/.." || exit 1

T=(); OPTS=(); NAME=
for a in "$@"; do
  case "$a" in
    *[!0-9]*|'') OPTS+=("$a"); NAME="$NAME-$(echo "$a" | tr -d -- '-')" ;;
    *) T=(-V "$a") ;;
  esac
done
W=${SNIF_FUZZ_DIR:-$HOME/snif-fuzz}
OUT=$W/out$NAME

mkdir -p "$W/build" "$W/corpus"
python3 fuzz/gen_corpus.py "$W/corpus" || exit 1

# one build shared by the campaigns: only when the sources changed
(
  flock 9
  if [ ! -x "$W/build/snif-fuzz" ] || [ -n "$(find . -maxdepth 1 \( -name '*.c' -o -name '*.h' \) -newer "$W/build/snif-fuzz")" ]; then
    cp ./*.c ./*.h "$W/build/"
    # its own config.h: the one of the source directory may come from another
    # machine, when the sources are shared
    cp configure config.h.in Makefile.in Makefile.am aclocal.m4 compile config.guess config.sub \
       depcomp install-sh missing "$W/build/" || exit 1
    rm -f "$W/build/config.h" "$W/build/snif-fuzz.new"
    (cd "$W/build" && ./configure > configure.out 2>&1) || { echo "configure failed: $W/build/configure.out"; exit 1; }
    (cd "$W/build" && AFL_USE_ASAN=1 afl-clang-fast -g -O1 -w -DHAVE_CONFIG_H -I. \
       -DPKGDATADIR='"/nonexistent"' ./*.c -o snif-fuzz.new -lpcap) || exit 1
    mv "$W/build/snif-fuzz.new" "$W/build/snif-fuzz"
  fi
) 9> "$W/build/.lock" || exit 1

export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
IN=$W/corpus
if [ -d "$OUT/default" ]; then # a previous run: go on with what it found
  IN=-
  for d in crashes hangs; do # the ones already seen are archived
    [ -n "$(ls "$OUT/default/$d" 2>/dev/null | grep -v README)" ] \
      && mv "$OUT/default/$d" "$OUT/default/$d.$(date +%Y%m%d-%H%M%S)"
  done
elif [ "$OUT" != "$W/out" ] && [ -d "$W/out/default/queue" ]; then
  # a new display: start from the packets found by the normal campaign too
  IN=$OUT.seeds
  rm -rf "$IN"; mkdir -p "$IN"
  cp "$W"/corpus/* "$IN"/
  n=0; for f in "$W"/out/default/queue/id:*; do n=$((n+1)); cp "$f" "$IN/q$n"; done
fi
# -s: no colors, -a: no tables to load (faster); the checksums are verified
exec afl-fuzz -i "$IN" -o "$OUT" -m none -t 2000 "${T[@]}" -- \
   "$W/build/snif-fuzz" -s -a "${OPTS[@]}" -f @@
