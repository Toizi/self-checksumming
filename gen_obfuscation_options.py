#!/usr/bin/env python
from __future__ import print_function
import os
import argparse
from itertools import combinations, permutations

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-length", help="the minimum length of the joined obfuscations", type=int, default=1)
    parser.add_argument("--max-length", help="the maximum length of the joined obfusactions", type=int, default=2)
    parser.add_argument("--coverages",
        help="comma separated list of obfuscation coverages to generate. E.g. --coverages 10,20",
        default="20")
    parser.add_argument("obfuscations", nargs='*', help="the obfuscation choices",
        default=['flatten', 'virt', 'opaque', 'subst', 'indir'])
    
    args = parser.parse_args(argv)
    if args.min_length > args.max_length:
        print('error: min length cannot be greater than max length')
    args.coverages = [int(coverage) for coverage in args.coverages.split(',')]
    return args

def main(argv):
    args = parse_args(argv)
    obfuscation_entries = []
    for i in range(args.min_length, args.max_length + 1):
        combs = combinations(args.obfuscations, i)
        for comb in combs:
            obfuscation_entries.extend(permutations(comb))
    
    results = []
    for coverage in args.coverages:
        # print(obfuscation_entries)
        for obfuscation in obfuscation_entries:
            # obfuscation: Tuple(str, str...)
            arg_str = ['{}.{}'.format(c, coverage) for c in obfuscation]
            results.append('-ob {}'.format(','.join(arg_str)))

        # coverage_results = ['-ob {}'.format(','.join(
        #     '{}.{}'.format(c, coverage))) for c in obfuscation_entries]
        # results.extend(coverage_results)


    print(' '.join(results))

if __name__ == '__main__':
    main(os.sys.argv[1:])
