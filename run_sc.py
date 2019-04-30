#!/usr/bin/env python
from __future__ import print_function
import argparse
import tempfile
import os
import subprocess
import shlex
from run_tigress import main as tigress_main

mydir = os.path.dirname(os.path.abspath(__file__))
os.sys.path.append(os.path.join(mydir, 'patcher'))
from dump_pipe import main as dump_main

tigress_options = {
    "virt":     "Virtualize",
    "flatten":  "Flatten",
}

obfuscation_options = []
obfuscation_options.extend(tigress_options.keys())

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--compile", help="compile only and produce an object file",
                        action="store_true")
    parser.add_argument("-ob", "--obfuscation", choices=obfuscation_options,
                        action='append',
                        help="obfuscation transformations used on the checker function")
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("-con", "--connectivity", help="desired connectiviy of the checkers network", type=float, default=2)
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
    UTILLIB = os.path.join(SC_BUILD, 'lib', 'libUtils.so')
    INPUTDEP_PATH = '/usr/local/lib'
    return SC_BUILD, SC_HOME

def run_cmd(cmd):
    try:
        subprocess.check_call(shlex.split(cmd))#, stdout=subprocess.STDOUT, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return False
    return True


def compile_to_bc(source_file, build_dir):
    cmd = "{compiler} {source} -c -emit-llvm -o {build_dir}/source.bc".format(compiler=CLANG, source=source_file, build_dir=build_dir)
    if not run_cmd(cmd):
        print("compile_to_bc failed:\n   {}".format(cmd))
        return False
    return True

def apply_selfchecking(connectivity, build_dir):
    cmd = '{opt} -load "{indep_path}/libInputDependency.so" -load "{util}" -load "{indep_path}/libTransforms.so" -load "{sc_build}/lib/libSCPass.so" -strip-debug -unreachableblockelim -globaldce -extract-functions -sc -connectivity={con} -dump-checkers-network="{build_dir}/network_file" -patch-guide="{build_dir}/patch_guide.txt" -dump-sc-stat="{build_dir}/sc.stats" -o "{build_dir}/guarded.bc" "{build_dir}/source.bc"'.format(opt=OPT, indep_path=INPUTDEP_PATH, util=UTILLIB, sc_build=SC_BUILD, con=connectivity, build_dir=build_dir)

    if not run_cmd(cmd):
        print("apply_selfchecking failed:\n   {}".format(cmd))
        return False
    return True

def obfuscate_guard(obfuscations, build_dir):
    rtlib_path = os.path.join(SC_HOME, 'rtlib.c')

    # no obfuscations specified, no need to obfuscate
    if not obfuscations:
        return rtlib_path

    # check for tigress obfuscations
    tigress_obfs = set(tigress_options.keys()) & set(obfuscations)
    if tigress_obfs:
        org_rtlib = rtlib_path
        rtlib_path = os.path.join(build_dir, 'rtlib_obf.c')
        transforms = ['--obfuscation {}'.format(tigress_options[obf]) for obf in tigress_obfs]
        tigress_args = '--out {out_file} {transforms} --functions=guardMe {input}'.format(out_file=rtlib_path, transforms=' '.join(transforms), input=org_rtlib)
        if not tigress_main(shlex.split(tigress_args)):
            print('obfuscate_guard failed')
            return False

    return rtlib_path

def compile_guard_to_bc(build_dir, guard_file):
    guard_bc = os.path.join(build_dir, 'guard.bc')
    cmd = "{compiler} {guard_file} -c -emit-llvm -o {out}".format(compiler=CLANG, guard_file=guard_file, out=guard_bc)
    if not run_cmd(cmd):
        print('compile_guard_to_bc failed:\n   {}'.format(cmd))
        return False

    return guard_bc

def link_guard_and_source(args, build_dir):
    guard_bc = os.path.join(build_dir, 'guard.bc')
    source_bc = os.path.join(build_dir, 'guarded.bc')
    cmd = "{linker} {guard_file} {source_file} -o {out}".format(linker=CLANG, guard_file=guard_bc, source_file=source_bc, out=args.output)
    if args.verbose:
        print(cmd)
    if not run_cmd(cmd):
        print('compile_guard_to_bc failed:\n   {}'.format(cmd))
        return False

    return True

def patch_binary(args, build_dir):
    dump_args = '"{out_file}" --patch-guide="{build_dir}/patch_guide.txt" --patch-dump="{build_dir}/patches.txt" --sc-stats="{build_dir}/sc.stats" -v'.format(out_file=args.output, build_dir=build_dir)
    if not dump_main(shlex.split(dump_args)):
        print('patch_binary failed')
        return False
    return True

def run(args):
    build_dir  = tempfile.mkdtemp()
    if args.verbose:
        print('[*] compile_to_bc')
    if not compile_to_bc(args.source_file, build_dir):
        print('[-] compile_to_bc')
        return False

    if args.verbose:
        print('[*] apply_selfchecking')
    if not apply_selfchecking(args.connectivity, build_dir):
        print('[-] apply_selfchecking')
        return False
    
    if args.verbose:
        print('[*] obfuscate_guard')
    guard_file = obfuscate_guard(args.obfuscation, build_dir)
    if not guard_file:
        print('[-] obfuscate_guard')
        return False

    if args.verbose:
        print('[*] compile_guard_to_bc')
    if not compile_guard_to_bc(build_dir, guard_file):
        print('[-] compile_guard_to_bc')
        return False

    if args.verbose:
        print('[*] link_guard_and_source')
    if not link_guard_and_source(args, build_dir):
        print('[-] link_guard_and_source')
        return False

    if args.verbose:
        print('[*] patch_binary')
    if not patch_binary(args, build_dir):
        print('[-] patch_binary')
        return False
    return True

def main(argv):
    args = parse_args(argv)
    setup_environment()
    run(args)

    if args.verbose:
        print('Done')
        print('Intermediate results in\n{}'.format(build_dir))
    return True

if __name__ == '__main__':
    main(os.sys.argv[1:])