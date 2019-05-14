#!/usr/bin/env python

# sequence diagram
# https://sequencediagram.org/index.html#initialData=C4S2BsFMAICMENgGMAW0kHsC2AHE4QA7Ac2mEgGdhocAnDY2+LCgKFfiWA1ugAV6jZlki0OXEADdEMAQyZYRYuUMWiAtAD4EyFAH1MufJAB0OAJ4AuWgFdCACgywAZjYpJEIDIQoAaaEQ4NsB6ACYgtACU4qDS5HCIqAbYeFBm5qw6SYapphZaWfo5xumWmOBQXHoUGDa0SJT2gcFhEdGs4BgYONBOru6e3mycsTLQtoTVSOmZiUUpJfmaE1OlSLSQMnp0GA0UFI4ubh6gQ+0r7ulaF9MWZQtQ1bX1kHrcerBI9tE3V8t2qzu8BwOHA5mqkHAzlQkCQAGsiMRvqxfktUVY+sctjD4aJkejrgDLndio8cXDRG8MB8vj8ibdzITJsSrARCHCDChYRTaHp4IRQk86g18fS-ujLDg5h8iPBaOZkbNdMkjGkLAAedTqCU7chcSChaAAamgFEhznU5MRcFl8tYoU2EjiMHRrEgAtYKgUSk16kKKtypQ2wDqhHtjtG8X9pLyGQdIykMngznIvC9wlEQA

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
    parser.add_argument("--print-only", action="store_true",
        help="only print the commands to compile but do not execute them")
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
    failed_cmds = []
    for cmd in cmds:
        if args.verbose or args.print_only:
            print('running {}'.format(cmd))
        if not args.print_only:
            if not run_cmd(cmd):
                failed_cmds.append(cmd)
    if failed_cmds:
        print('[-] {} command(s) failed'.format(len(failed_cmds)))
        for failed_cmd in failed_cmds:
            print(failed_cmd)
        return False

    print('[{}] Done'.format('-' if failed_cmds else '+'))
    return True

if __name__ == '__main__':
    main(os.sys.argv[1:])