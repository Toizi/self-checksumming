#!/usr/bin/env python3
from __future__ import print_function
import argparse
import tempfile
import os
import subprocess
import shlex
import shutil
import traceback
import json

mydir = os.path.dirname(os.path.abspath(__file__))
os.sys.path.append(os.path.join(mydir, 'patcher'))
# from dump_pipe import main as dump_main

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("--build-dir", help="output path", required=False)
    parser.add_argument("-bc", "--compile-bc", help="input file is bitcode", action="store_true", required=False)
    parser.add_argument("-cpp", "--compile-cpp", help="use clang++ instead of clang", action="store_true", required=False)
    parser.add_argument("--link-args", help="arguments that are passed to the linker", required=False)
    parser.add_argument("--to-bitcode", help="only apply checking/obfuscation but do not link", action="store_true", required=False)
    parser.add_argument("source_file")
    
    args = parser.parse_args(argv)

    if not args.output:
        args.output, _ = os.path.splitext(args.source_file)
    return args

def setup_environment():
    global CLANG, CLANGPP, OPT, LLC, LLVM_LINK, SC_BUILD, SC_HOME, UTILLIB, INPUTDEP_PATH
    llvm_version = "-6.0"
    CLANG       = "clang{}".format(llvm_version)
    CLANGPP     = "clang++{}".format(llvm_version)
    OPT         = "opt{}".format(llvm_version)
    LLC         = "llc{}".format(llvm_version)
    LLVM_LINK   = "llvm-link{}".format(llvm_version)

    mydir   = os.path.dirname(os.path.abspath(__file__))
    SC_BUILD= os.path.join(mydir, "build")
    SC_HOME = mydir
    return SC_BUILD, SC_HOME

def run_cmd(cmd, log_file=None):
    # print('run_cmd: {}'.format(cmd))
    try:
        subprocess.check_call(shlex.split(cmd) if isinstance(cmd, str) else cmd,
            stdout=log_file,
            stderr=log_file)
    except subprocess.CalledProcessError:
        traceback.print_exc()
        return False
    return True


def compile_source_to_bc(source_file, build_dir):
    source_bc = os.path.join(build_dir, "source.bc")
    cmd = "{compiler} {source} -c -emit-llvm -o {out}".format(compiler=CLANG, source=source_file, out=source_bc)
    if not run_cmd(cmd):
        print("compile_source_to_bc failed:\n   {}".format(cmd))
        return False
    return source_bc


def link(args, checked_bc):
    cmd = "{linker} {source_file} -o {out}".format(linker=CLANGPP if args.compile_cpp else CLANG, source_file=checked_bc, out=args.output)
    if args.link_args:
        cmd += ' {}'.format(args.link_args)
    if args.verbose:
        print(cmd)
    if not run_cmd(cmd):
        print('link failed:\n   {}'.format(cmd))
        return False

    return args.output

def run(args, build_dir):

    if args.compile_bc:
        if args.verbose:
            print('[*] skipping compile_source_to_bc since input file is bitcode already')
        source_bc = args.source_file
    else:
        if args.verbose:
            print('[*] compile_source_to_bc')
        source_bc = compile_source_to_bc(args.source_file, build_dir)
        if not source_bc:
            print('[-] compile_source_to_bc')
            return False

    if args.verbose:
        print('[*] link')
    if args.to_bitcode:
        shutil.copyfile(obf_checked_bc, args.output)
        print('[*] --to-bitcode specified, skipping link')
        return True
    out_file = link(args, source_bc)
    if not out_file:
        print('[-] link')
        return False

    return True

def main(argv):
    args = parse_args(argv)
    setup_environment()
    build_dir = args.build_dir if args.build_dir else tempfile.mkdtemp()
    result = run(args, build_dir)

    if args.verbose:
        print('Done')
        print('Intermediate results in\n{}'.format(build_dir))
    return result

if __name__ == '__main__':
    if main(os.sys.argv[1:]) is not True:
        exit(1)
