#!/usr/bin/env python
from __future__ import print_function
from glob import glob
import os
import argparse
from pprint import pprint
import subprocess
import shlex

def run_cmd(cmd):
    try:
        subprocess.check_call(shlex.split(cmd))#, stdout=subprocess.STDOUT, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return False
    return True

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("-ob", "--obfuscation", help="list of obfuscations",
                        action='append', required=False)
    parser.add_argument("input_dir", type=str)

    args = parser.parse_args(argv)

    # create output dir from input dir if no output was specified
    if not args.output:
        parent_dir, dir_name = os.path.split(os.path.abspath(args.input_dir))
        args.output = os.path.join(parent_dir, dir_name + '_bin')

    # make sure directory ends with separator to allow globbing
    if args.input_dir[-1] != os.path.sep:
        args.input_dir += os.path.sep

    return args

def main(argv):
    args = parse_args(argv)
    files = glob(args.input_dir + '*.c')
    if args.verbose:
        print('input files : {}'.format(files))
        print('obfuscations: {}'.format(args.obfuscation))
    
    mydir   = os.path.dirname(os.path.abspath(__file__))
    run_sc  = os.path.join(mydir, 'run_sc.py')
    cmds = []
    for obf in args.obfuscation:
        obfuscations = obf.split(',')
        # generate obfuscation string
        obf_str = ' '.join(["--obfuscation {}".format(o) for o in obfuscations])
        # generate output filename
        out_fname_id = '-'.join(obfuscations)

        for fpath in files:
            # get output name
            out_name, _ = os.path.splitext(os.path.basename(fpath))
            # extension is only requried on windows
            ext = '.exe' if os.name == 'nt' else ''
            out_name = '{}+{}{}'.format(out_name, out_fname_id, ext)
            out_path = os.path.join(args.output, out_name)
            cmd = '"{run}" {obf} "{source}" -o "{out}"'.format(
                run=run_sc, obf=obf_str, source=fpath, out=out_path)
            cmds.append(cmd)
    if args.verbose:
        pprint(cmds)
    print('[*] creating output dir {}'.format(args.output))
    os.mkdir(args.output)
    for cmd in cmds:
        if args.verbose:
            print('running {}'.format(cmd))
        run_cmd(cmd)

if __name__ == '__main__':
    main(os.sys.argv[1:])