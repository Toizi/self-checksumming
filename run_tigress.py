#!/usr/bin/env python
from __future__ import print_function
import argparse
import os
import subprocess
import shlex
import re

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-ob", "--obfuscation", required=True,
                        action='append',
                        help="obfuscation transformations used on the checker function")
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-f", "--functions", help="the functions the obfuscation should be applied to", nargs="+")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("-con", "--connectivity", help="desired connectiviy of the checkers network")
    parser.add_argument("source_file")
    
    return parser.parse_args(argv)

def setup_environment(args):
    mydir = os.path.dirname(os.path.abspath(__file__))
    TIGRESS_DIR = os.path.join(mydir, "obfuscation", "tigress-2.2")
    TIGRESS = os.path.join(TIGRESS_DIR, "tigress")
    TIGRESS_ENV = os.environ
    TIGRESS_ENV['PATH'] += TIGRESS_DIR
    TIGRESS_ENV['TIGRESS_HOME'] = TIGRESS_DIR
    return TIGRESS_DIR, TIGRESS, TIGRESS_ENV

def replace_main(src):
    return re.sub(r" main\(", " not_main(", src)

def run(args, TIGRESS_DIR, TIGRESS, TIGRESS_ENV):
    try:
        with open(args.source_file, 'r') as f:
            input_text = f.read()
    except IOError:
        print('could not open file {}'.format(args.source_file))
        return False
    source_contains_main = input_text.find(' main\(') >= 0
    del input_text

    if args.functions:
        functions_str = '--Functions={}'.format(','.join(args.functions))
    else:
        functions_str = '--Functions=*'
    transforms = ["--Transform={} {}".format(obf, functions_str) for obf in args.obfuscation]

    if args.output:
        out_file = args.output
    else:
        out_file, ext = os.path.splitext(args.source_file)
        out_file = '{}_obf{}'.format(out_file, ext)

    cmd = '{tigress} --out="{out}" {transforms} {src}'.format(tigress=TIGRESS, out=out_file, transforms=' '.join(transforms), src=args.source_file)
    if args.verbose:
        print(cmd)
    try:
        subprocess.check_call(shlex.split(cmd), env=TIGRESS_ENV)
    except subprocess.CalledProcessError:
        print('run_tigress failed:\n   {}'.format(cmd))
        return False
    if not source_contains_main:
        try:
            with open(out_file, 'r') as f:
                output_text = f.read()
        except IOError:
            print('could not open output file for reading {}'.format(out_file))
            return False
        mainless_text = replace_main(output_text)        
        try:
            with open(out_file, 'w') as f:
                f.write(mainless_text)
        except IOError:
            print('could not open output file for writing {}'.format(out_file))

    return True

def main(argv):
    args = parse_args(argv)
    TIGRESS_DIR, TIGRESS, TIGRESS_ENV = setup_environment(args)
    if not run(args, TIGRESS_DIR, TIGRESS, TIGRESS_ENV):
        return False
    return True

if __name__ == '__main__':
    main(os.sys.argv[1:])