#!/usr/bin/env python3

from __future__ import print_function
from glob import glob
import os
import argparse
from pprint import pprint
import shlex
import shutil
import traceback
import re
import tempfile
import json
from benchexec.runexecutor import RunExecutor
from benchexec.container import (
    DIR_MODES,
    DIR_HIDDEN,
    DIR_READ_ONLY,
    DIR_OVERLAY,
    DIR_FULL_ACCESS
)

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("-i", "--iterations",
        help="number of times the benchmarks will be repeated",
        default=1,
        type=int)
    parser.add_argument("--print-only", action="store_true",
        help="only print the commands but do not execute them")
    parser.add_argument("--clean-first",
        help="recursively remove the output directory if it exists already",
        action="store_true")
    parser.add_argument("--keep-build-dir",
        help="keep the build dir that contains output logs of the executions",
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

    return args

def main(argv):
    args = parse_args(argv)
    mydir = os.path.dirname(os.path.abspath(__file__))
    libminm_path = os.path.join(mydir, 'hook/build/libminm_env.so')
    cmd_infos_path = os.path.join(mydir, 'samples/cmdline-args/cmdline.json')
    cmdline_dir = os.path.join(mydir, 'samples/cmdline-args')
    build_dir = tempfile.mkdtemp()
    # build_dir = os.path.join(mydir, 'samples/tmp_builddir')
    # os.mkdir(build_dir)

    with open(cmd_infos_path, 'r') as f:
        cmd_infos = json.load(f)

    if args.verbose:
        print('[*] build directory : {}'.format(build_dir))
        print('[*] output directory: {}'.format(args.output))
    
    # remove output directory if required
    if args.clean_first and os.path.exists(args.output):
        if args.verbose:
            print('[*] clean first specified. removing output directory')
        shutil.rmtree(args.output)
    if os.path.exists(args.output):
        print('[-] output directory exists already')
        print('[*] specify --clean-first to remove it automatically')
        return False
    
    seed_glob_str = args.input_dir + 'seed_*/'
    seed_dirs = glob(seed_glob_str)
    if args.verbose:
        print('[*] globbing seed dir result: {}'.format(seed_dirs))

    print('[*] creating output dir {}'.format(args.output))
    os.mkdir(args.output)
    for seed_dir in seed_dirs:
        # name of the seed directory
        seed_name = os.path.basename(os.path.abspath(seed_dir))
        # output directory
        seed_output = os.path.join(args.output, seed_name)
        # tmp working dirs
        seed_working_dir = os.path.join(build_dir, seed_name)
        os.mkdir(seed_working_dir)

        # make sure we can glob correctly
        if seed_dir[-1] != os.sep:
            seed_dir = seed_dir + os.sep
        glob_str = seed_dir + '*'
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
            sample_name = os.path.basename(sample)
            original_name = sample_name.rpartition('+')[0]

            # create working dir for sample
            sample_working_dir = os.path.join(seed_working_dir, sample_name)
            os.mkdir(sample_working_dir)

            # get cmd info
            cmd_info = cmd_infos.get(original_name)
            if not cmd_info:
                print('[-] no cmd_info found for {}'.format(original_name))
                return False

            # copy required files to tmp dir
            for req_file in cmd_info['required_files']:
                shutil.copy(os.path.join(cmdline_dir, req_file), sample_working_dir)
            cmd_list = [sample]
            cmd_list.extend(cmd_info['args'])
            # some programs exit with something other than 0 on success...
            success_exit_code = cmd_info.get('success_exit_code', 0)
            cmd = (cmd_list, sample_working_dir, success_exit_code, cmd_info.get('env'))
            cmds.append(cmd)

        if args.verbose:
            pprint(cmds)

        print('[*] creating intermediate output dir {}'.format(seed_output))
        os.mkdir(seed_output)

        print('[*] Running commands')
        try:
            from tqdm import tqdm
            exec_iterator = tqdm(range(args.iterations))
        except ImportError:
            exec_iterator = range(args.iterations)
        # run each command param iteration times
        for i in exec_iterator:
            for cmd in cmds:
                if args.verbose or args.print_only:
                    print('running {}'.format(' '.join(cmd[0])))
                if args.print_only:
                    continue

                # create the output log in the working dir
                output_path = os.path.join(cmd[1], 'output.txt')

                executor = RunExecutor(dir_modes={
                    "/": DIR_OVERLAY,
                    "/run": DIR_HIDDEN,
                    "/tmp": DIR_HIDDEN,
                    build_dir: DIR_FULL_ACCESS})

                # prepare environment
                env = os.environ
                if cmd[3]:
                    for key, val in cmd[3].items():
                        env[key] = val
                # env['LD_PRELOAD'] = libminm_path
                if args.verbose:
                    print('working dir: {}'.format(cmd[1]))
                    # print('environment: {}'.format(env))
                run = executor.execute_run(cmd[0], output_path, workingDir=cmd[1], environments=env)
                exitcode = run['exitcode']
                if exitcode.value != cmd[2]:
                    print(exitcode)
                    print('[-] command failed: {}'.format(' '.join(cmd[0])))
                    print('output at: {}'.format(output_path))
                    return False

                result_path = os.path.join(seed_output, 'result_' + os.path.basename(cmd[0][0]) + '_' + str(i))
                with open(result_path, 'w') as f:
                    json.dump(run, f)

    if args.keep_build_dir:
        print('[*] keeping build dir: {}'.format(build_dir))
    else:
        print('[*] removing build dir: {}'.format(build_dir))
        shutil.rmtree(build_dir)

    print('[+] Done')
    return True

if __name__ == '__main__':
    if main(os.sys.argv[1:]) is not True:
        exit(1)
