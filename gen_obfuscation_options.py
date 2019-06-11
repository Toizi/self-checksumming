#!/usr/bin/env python
from __future__ import print_function
import os
import argparse
from itertools import combinations, permutations

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-length", help="the minimum length of the joined obfuscations", type=int, default=1)
    parser.add_argument("--max-length", help="the maximum length of the joined obfusactions", type=int, default=2)
    parser.add_argument("obfuscations", nargs='*', help="the obfuscation choices",
        default=['flatten', 'virt', 'opaque', 'subst', 'indir'])
    
    args = parser.parse_args(argv)
    if args.min_length > args.max_length:
        print('error: min length cannot be greater than max length')
    return args

def main(argv):
    args = parse_args(argv)
    results = []
    for i in range(args.min_length, args.max_length + 1):
        combs = combinations(args.obfuscations, i)
        for comb in combs:
            results.extend(permutations(comb))

    results = ['-ob {}'.format(','.join(c)) for c in results]
    print(' '.join(results))

if __name__ == '__main__':
    main(os.sys.argv[1:])
