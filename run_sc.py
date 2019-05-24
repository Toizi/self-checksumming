#!/usr/bin/env python
from __future__ import print_function
import argparse
import tempfile
import os
import subprocess
import shlex
import traceback
from run_tigress import main as tigress_main

mydir = os.path.dirname(os.path.abspath(__file__))
os.sys.path.append(os.path.join(mydir, 'patcher'))
from dump_pipe import main as dump_main

tigress_options = {
    "virt":     "Virtualize",
    "flatten":  "Flatten",
}

scvirt_options = {
    "virt":   "-scvirt",
}

ollvm_options = {
    "opaque":    "-bcf",
    "subst":     "-sub",
    "indir":     "-cfg-indirect",
}

obfuscation_options = ['none']
# obfuscation_options.extend(tigress_options.keys())
obfuscation_options.extend(ollvm_options.keys())
obfuscation_options.extend(scvirt_options.keys())

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

def run_cmd(cmd, log_file=None):
    # print('run_cmd: {}'.format(cmd))
    try:
        subprocess.check_call(shlex.split(cmd) if isinstance(cmd, basestring) else cmd,
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

def apply_selfchecking(connectivity, build_dir, source_bc, checker_bc):
    checked_bc = os.path.join(build_dir, 'checked.bc')
    cmd = '{opt} -load "{indep_path}/libInputDependency.so" -load "{util}" -load "{indep_path}/libTransforms.so" -load "{sc_build}/lib/libSCPass.so" -strip-debug -unreachableblockelim -globaldce -extract-functions -sc -connectivity={con} -dump-checkers-network="{build_dir}/network_file" -patch-guide="{build_dir}/patch_guide.txt" -dump-sc-stat="{build_dir}/sc.stats" -checker-bitcode={checker} -o "{out}" "{src}"'.format(opt=OPT, indep_path=INPUTDEP_PATH, util=UTILLIB, sc_build=SC_BUILD, con=connectivity, build_dir=build_dir, src=source_bc, out=checked_bc, checker=checker_bc)

    if not run_cmd(cmd):
        print("apply_selfchecking failed:\n   {}".format(cmd))
        return False
    return checked_bc

def obfuscate_checker_src(obfuscations, build_dir):
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
            print('obfuscate_checker_src failed')
            return False

    return rtlib_path

def obfuscate_bc(obfuscations, build_dir, checker_bc):
    ollvm_bin = os.path.join(SC_HOME, 'obfuscation/Obfuscator-LLVM/build/bin')
    scvirt_opt = os.path.join(SC_HOME, 'obfuscation/sc-virt-master/build/bin/opt')
    scvirt_lib = os.path.join(SC_HOME, 'obfuscation/sc-virt-master/build/lib/LLVMScVirt.so')

    # no obfuscations specified, no need to obfuscate
    if not obfuscations:
        return checker_bc
    
    # scvirt,opaque,indir,scvirt
    # => [[scvirt], [opaque, indir], [scvirt]]
    log_dir = os.path.join(build_dir, 'obfuscate_checker_bc.log')
    bc_input = checker_bc
    checker_bc = os.path.join(build_dir, 'checker_obf.bc')
    with open(log_dir, 'w') as log_dir_f:
        # since scvirt/ollvm use opt/clang, apply every transformation
        # individually (slower but easier. should be using the same in the end)
        for obf in obfuscations:
            # check for ollvm obfuscations
            if obf in ollvm_options or obf == 'none':
                transforms = [] if obf == 'none' else ['-mllvm', ollvm_options[obf]]
                cmd = [os.path.join(ollvm_bin, 'clang'),
                    '-o', checker_bc,
                    '-c', '-emit-llvm',
                    bc_input,
                ]
                cmd.extend(transforms)
                print('running {} > {}'.format(' '.join(cmd), log_dir))
                log_dir_f.write('obfuscation: {}\n'.format(obf))
                success = run_cmd(cmd, log_dir_f)
                if not success:
                    print('obfuscate_checker_bc failed')
                    return False
                bc_input = checker_bc
            elif obf in scvirt_options:
                cmd = [ scvirt_opt,
                    '-o', checker_bc,
                    '-load', scvirt_lib,
                    scvirt_options[obf],
                    '-dump-file', os.path.join(build_dir, 'scvirt_stats.txt'),
                    bc_input
                ]
                print('running {} > {}'.format(' '.join(cmd), log_dir))
                log_dir_f.write('obfuscation: {}\n'.format(obf))
                success = run_cmd(cmd, log_dir_f)
                if not success:
                    print('obfuscate_checker_bc failed')
                    return False
                bc_input = checker_bc
            else:
                print("unknown obfuscation option {}".format(obf))
                return False

    return checker_bc

def obfuscate_checker_bc(obfuscations, build_dir, checker_bc):
    ollvm_bin = os.path.join(SC_HOME, 'obfuscation/Obfuscator-LLVM/build/bin')

    # no obfuscations specified, no need to obfuscate
    if not obfuscations:
        return checker_bc

    # check for ollvm obfuscations
    ollvm_obfs = set(ollvm_options.keys()) & set(obfuscations)
    if ollvm_obfs:
        org_checker = checker_bc
        checker_bc = os.path.join(build_dir, 'checker_obf.bc')
        transforms = [ollvm_options[obf] for obf in ollvm_obfs]
        cmd = [os.path.join(ollvm_bin, 'clang'),
            '-o', checker_bc,
            '-c', '-emit-llvm',
            org_checker,
        ]
        for transform in transforms:
            cmd.append('-mllvm')
            cmd.append(transform)
        # '--out {out_file} {transforms} --functions=guardMe {input}'.format(out_file=rtlib_path, transforms=' '.join(transforms), input=org_rtlib)]
        log_dir = os.path.join(build_dir, 'obfuscate_checker_bc.log')
        print('running {} > {}'.format(' '.join(cmd), log_dir))
        with open(log_dir, 'w') as f:
            success = run_cmd(cmd, f)
        if not success:
            print('obfuscate_checker_bc failed')
            return False

    return checker_bc

def compile_checker_to_bc(build_dir, checker_file):
    checker_bc = os.path.join(build_dir, 'checker.bc')
    cmd = "{compiler} {checker_file} -c -emit-llvm -o {out}".format(compiler=CLANG, checker_file=checker_file, out=checker_bc)
    if not run_cmd(cmd):
        print('compile_checker_to_bc failed:\n   {}'.format(cmd))
        return False

    return checker_bc

def link_checker_and_source(args, build_dir, source_bc, checker_bc):
    cmd = "{linker} {checker_file} {source_file} -o {out}".format(linker=CLANG, checker_file=checker_bc, source_file=source_bc, out=args.output)
    if args.verbose:
        print(cmd)
    if not run_cmd(cmd):
        return False

    return args.output

def link(args, checked_bc):
    cmd = "{linker} {source_file} -o {out}".format(linker=CLANG, source_file=checked_bc, out=args.output)
    if args.verbose:
        print(cmd)
    if not run_cmd(cmd):
        print('link failed:\n   {}'.format(cmd))
        return False

    return args.output

def patch_binary(args, build_dir, out_file):
    dump_args = '"{out_file}" --patch-guide="{build_dir}/patch_guide.txt" --patch-dump="{build_dir}/patches.txt" --sc-stats="{build_dir}/sc.stats" -v'.format(out_file=out_file, build_dir=build_dir)
    if not dump_main(shlex.split(dump_args)):
        print('patch_binary failed')
        return False
    return True

def run(args, build_dir):
    # if args.verbose:
    #     print('[*] obfuscate_checker_src')
    # checker_file = obfuscate_checker_src(args.obfuscation, build_dir)
    # if not checker_file:
    #     print('[-] obfuscate_checker_src')
    #     return False
    checker_file = os.path.join(SC_HOME, 'rtlib.c')

    if args.verbose:
        print('[*] compile_checker_to_bc')
    checker_bc = compile_checker_to_bc(build_dir, checker_file)
    if not checker_bc:
        print('[-] compile_checker_to_bc')
        return False

    # if args.verbose:
    #     print('[*] obfuscate_checker_bc')
    # checker_bc = obfuscate_checker_bc(args.obfuscation, build_dir, checker_bc)
    # if not checker_bc:
    #     print('[-] obfuscate_checker_bc')
    #     return False

    if args.verbose:
        print('[*] compile_source_to_bc')
    source_bc = compile_source_to_bc(args.source_file, build_dir)
    if not source_bc:
        print('[-] compile_source_to_bc')
        return False

    if args.verbose:
        print('[*] apply_selfchecking')
    checked_bc = apply_selfchecking(args.connectivity, build_dir, source_bc, checker_bc)
    if not checked_bc:
        print('[-] apply_selfchecking')
        return False

    if args.verbose:
        print('[*] obfuscate_program_bc')
    obf_checked_bc = obfuscate_bc(args.obfuscation, build_dir, checked_bc)
    if not obf_checked_bc:
        print('[-] obfuscate_program_bc')
        return False

    if args.verbose:
        print('[*] link')
    out_file = link(args, obf_checked_bc)
    if not out_file:
        print('[-] link')
        return False
    # if args.verbose:
    #     print('[*] link_checker_and_source')
    # out_file = link_checker_and_source(args, build_dir, checked_bc, checker_bc)
    # if not out_file:
    #     print('[-] link_checker_and_source')
    #     return False

    if args.verbose:
        print('[*] patch_binary')
    if not patch_binary(args, build_dir, out_file):
        print('[-] patch_binary')
        return False
    return True

def main(argv):
    args = parse_args(argv)
    setup_environment()
    build_dir  = tempfile.mkdtemp()
    result = run(args, build_dir)

    if args.verbose:
        print('Done')
        print('Intermediate results in\n{}'.format(build_dir))
    return result

if __name__ == '__main__':
    if main(os.sys.argv[1:]) is not True:
        exit(1)