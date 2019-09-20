#!/bin/bash

set -e
rm -r ./samples/crispy-doom/build_sc_compare
mkdir ./samples/crispy-doom/build_sc_compare
./batch_compile_game.py --game crispy-doom samples/crispy-doom/build -o samples/crispy-doom/build_sc_compare/full -ob none.0 --connectivity 2 --sc-ratio=1 -j1
./batch_compile_game.py --game crispy-doom samples/crispy-doom/build -o samples/crispy-doom/build_sc_compare/targeted -ob none.0 -j1
mkdir -p ./samples/crispy-doom/build_sc_compare/nocheck/seed_1
THIS_DIR=$(pwd)
cd ./samples/crispy-doom/build
clang-6.0 src/crispy-doom.bc -DNDEBUG src/doom/libdoom.a /usr/lib/x86_64-linux-gnu/libSDL2main.a /usr/lib/x86_64-linux-gnu/libSDL2.so /usr/lib/x86_64-linux-gnu/libSDL2_mixer.so /usr/lib/x86_64-linux-gnu/libSDL2_net.so textscreen/libtextscreen.a pcsound/libpcsound.a opl/libopl.a /usr/lib/x86_64-linux-gnu/libpng.so -lm /usr/lib/x86_64-linux-gnu/libSDL2_mixer.so /usr/lib/x86_64-linux-gnu/libSDL2.so /usr/lib/x86_64-linux-gnu/libz.so -o $THIS_DIR/samples/crispy-doom/build_sc_compare/nocheck/seed_1/crispy-doom+none.0
cd $THIS_DIR
echo "done"
