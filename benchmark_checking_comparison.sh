#!/bin/bash
set -e
./batch_benchmark_crispy.py --demo-file samples/crispy-doom/build_bench/fps_demo.lmp samples/crispy-doom/build_sc_compare/full -v --clean-first -i 2
./batch_benchmark_crispy.py --demo-file samples/crispy-doom/build_bench/fps_demo.lmp samples/crispy-doom/build_sc_compare/nocheck -v --clean-first -i 2
./batch_benchmark_crispy.py --demo-file samples/crispy-doom/build_bench/fps_demo.lmp samples/crispy-doom/build_sc_compare/targeted -v --clean-first -i 2