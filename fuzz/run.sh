#!/bin/bash
# Fuzzing of the decoders of snif with AFL++ (packages afl++ and clang).
#   ./fuzz/run.sh           build, then fuzz until Ctrl-C
#   ./fuzz/run.sh 3600      the same, for one hour
# The crashes are in fuzz/out/default/crashes/, to replay with:
#   fuzz/build/snif-fuzz -s -a -f fuzz/out/default/crashes/id:...
cd "$(dirname "$0")/.." || exit 1
mkdir -p fuzz/build fuzz/corpus
[ -n "$(ls fuzz/corpus 2>/dev/null)" ] || python3 fuzz/gen_corpus.py fuzz/corpus
cp *.c *.h fuzz/build/
(cd fuzz/build && AFL_USE_ASAN=1 afl-clang-fast -g -O1 -w -DHAVE_CONFIG_H -I. \
   -DPKGDATADIR='"/nonexistent"' ./*.c -o snif-fuzz -lpcap) || exit 1
export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=${AFL_NO_UI:-}
# -s: no colors, -a: no tables to load (faster), -K: no checksums
T=(); [ -n "$1" ] && T=(-V "$1")
IN=fuzz/corpus
if [ -d fuzz/out/default ]; then # a previous run: go on with what it found
  IN=-
  for d in crashes hangs; do # the ones already seen are archived
    [ -n "$(ls fuzz/out/default/$d 2>/dev/null | grep -v README)" ] \
      && mv fuzz/out/default/$d fuzz/out/default/$d.$(date +%Y%m%d-%H%M%S)
  done
fi
exec afl-fuzz -i $IN -o fuzz/out -m none -t 2000 "${T[@]}" -- \
   fuzz/build/snif-fuzz -s -a -K -f @@
