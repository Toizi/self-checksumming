#!/usr/bin/env python

from __future__ import print_function
from glob import glob
import os
import argparse
from pprint import pprint
import subprocess
import shlex
import shutil
import traceback
import re
import tempfile

VOGLPERF_LOCATION = '/home/marius/dev/voglperf/bin/voglperfrun64'

def run_cmd(cmd, cwd=None):
    try:
        subprocess.check_call(shlex.split(cmd), cwd=cwd)#, stdout=subprocess.STDOUT, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return cmd
    return True

def run_cmd_output(cmd, cwd=None):
    try:
        output = subprocess.check_output(cmd, cwd=cwd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return (e.returncode, e.stdout.decode())
    return (0, output.decode())

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("--demo-file",
        help="path to the demo file. Uses input_dir/fps_demo.lmp by default",
        required=False)
    parser.add_argument("--print-only", action="store_true",
        help="only print the commands but do not execute them")
    parser.add_argument("--clean-first",
        help="recursively remove the output directory if it exists already",
        action="store_true")
    parser.add_argument("input_dir", help="src directory of sauerbraten", type=str)

    args = parser.parse_args(argv)

    # generate output dir from input dir if no output was specified
    if not args.output:
        args.output = os.path.join(args.input_dir, 'benchmarks')
    args.output = os.path.abspath(args.output)

    # make sure directory ends with separator to allow globbing
    args.input_dir = os.path.abspath(args.input_dir)
    if args.input_dir[-1] != os.path.sep:
        args.input_dir += os.path.sep

    # set default demo path if none specified
    if not args.demo_file:
        args.demo_file = os.path.join(args.input_dir, 'fps_demo.lmp')

    return args

def main(argv):
    args = parse_args(argv)
    mydir = os.path.dirname(os.path.abspath(__file__))
    org_config_path = os.path.join(mydir, 'crispy-doom.cfg')
    build_dir = tempfile.mkdtemp()
    args.config_path = shutil.copy(org_config_path, build_dir)

    if not os.path.exists(VOGLPERF_LOCATION):
        print('[-] VOGLPERF_LOCATION ({}) does not exist'.format(
            VOGLPERF_LOCATION))
        return False

    if args.verbose:
        print('[*] output directory: {}'.format(args.output))
        print('[*] demo file: {}'.format(args.demo_file))
    
    # remove output directory if required
    if args.clean_first and os.path.exists(args.output):
        if args.verbose:
            print('[*] clean first specified. removing output directory')
        shutil.rmtree(args.output)
    if os.path.exists(args.output):
        print('[-] output directory exists already')
        print('[*] specify --clean-first to remove it automatically')
        return False
    
    glob_str = args.input_dir + 'crispy-doom+*'
    if args.verbose:
        print('[*] globbing for samples: {}'.format(glob_str))
    samples = glob(glob_str)
    if args.verbose:
        print('[*] globbing result: {}'.format(samples))
    if not samples:
        print('[-] no samples found with glob {}'.format(glob_str))
        return False


    # build all of the commands
    cmds = []
    for sample in samples:
        cmd = [
            VOGLPERF_LOCATION, '--logfile', '--fpsshow', '--',
            sample, '-nosound', '-playdemo', args.demo_file,
            '-extraconfig', args.config_path
        ]
        cmds.append(cmd)

    if args.verbose:
        pprint(cmds)

    print('[*] creating output dir {}'.format(args.output))
    os.mkdir(args.output)

    # go through all commands and launch them
    for cmd in cmds:
        if args.verbose or args.print_only:
            print('running {}'.format(' '.join(cmd)))
        if args.print_only:
            continue

        # run command and check whether it was successful
        retcode, output = run_cmd_output(cmd)
        if retcode != 0:
            print('[-] command failed: {}'.format(' '.join(cmd)))
            print('output: {}'.format(output))
            return False
        
        # parse output for logfile location
        logfile_pattern = r'\(voglperf\) logfile_close\((.*?\.csv)\)'
        match = re.search(logfile_pattern, output)
        if not match:
            print('[-] could not find logfile in voglperf output')
            print('regex: ', logfile_pattern)
            print('output: ', output)
            return False
        logfile_loc = match.group(1)
            
        # copy the logfile to the output directory
        shutil.copy(logfile_loc, args.output)


    print('[+] Done')
    return True

if __name__ == '__main__':
    if main(os.sys.argv[1:]) is not True:
        exit(1)
