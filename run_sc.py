#!/usr/bin/env python
from __future__ import print_function
import argparse
import tempfile
import os
import subprocess
import shlex
import shutil
import traceback
import json
from run_tigress import main as tigress_main

mydir = os.path.dirname(os.path.abspath(__file__))
os.sys.path.append(os.path.join(mydir, 'patcher'))
# from dump_pipe import main as dump_main
ghidra_dump_path = os.path.join(mydir, 'patcher', 'ghidra_patch.py')
ghidra_headless = 'analyzeHeadless'

tigress_options = {
    "virt":     "Virtualize",
    "flatten":  "Flatten",
}

scvirt_options = {
    "virt":   {
        "pass_name": "-scvirt",
        "coverage_name": "-scvirt-ratio"
    }
}

ollvm_options = {
    "opaque":    {
        "pass_name": "-opaque-predicate",
        "coverage_name": "-opaque-ratio"
    },
    "subst": {
        "pass_name": "-substitution",
        "coverage_name": "-substitution-ratio"
    },
    "indir": {
        "pass_name": "-cfg-indirect",
        "coverage_name": "-cfg-indirect-ratio"
    },
    "flatten": {
        "pass_name": "-flattening",
        "coverage_name": "-flatten-ratio"
    },
}

obfuscation_options = ['none']
# obfuscation_options.extend(tigress_options.keys())
obfuscation_options.extend(ollvm_options.keys())
obfuscation_options.extend(scvirt_options.keys())

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--compile", help="compile only and produce an object file",
                        action="store_true")
    parser.add_argument("-ob", "--obfuscation",
                        action='append',
                        help='\n'.join(
                            ["Obfuscation transformations used on the checker function.",
                            "format is obf_name.coverage.",
                            "E.g. indir.10 to obfuscate 10%% of the functions",
                            "in addition to the checker functions since these will always be obfuscated.",
                            "Options are: {}".format(', '.join(obfuscation_options))]))
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("--build-dir", help="output path", required=False)
    parser.add_argument("-bc", "--compile-bc", help="input file is bitcode", action="store_true", required=False)
    parser.add_argument("-cpp", "--compile-cpp", help="use clang++ instead of clang", action="store_true", required=False)
    parser.add_argument("--checked-functions", help="comma separated list of functions to be protected", required=False)
    parser.add_argument("--link-args", help="arguments that are passed to the linker", required=False)
    parser.add_argument("--to-bitcode", help="only apply checking/obfuscation but do not link", action="store_true", required=False)
    parser.add_argument("--patch-only", help="only patch the binary", action="store_true", required=False)
    parser.add_argument("-con", "--connectivity", help="desired connectiviy of the checkers network", type=int, default=2)
    parser.add_argument("source_file")
    
    args = parser.parse_args(argv)

    if args.patch_only:
        if not args.build_dir:
            print("[-] --patch-only requires setting --build-dir")
    if not args.output:
        args.output, _ = os.path.splitext(args.source_file)
        if args.output == args.source_file:
            args.output += '_patched'
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

def apply_selfchecking(connectivity, build_dir, source_bc, checker_bc, checked_functions_str, checker_functions_path):
    checked_bc = os.path.join(build_dir, 'checked.bc')
    # -load "{indep_path}/libInputDependency.so" 
    # -load "{indep_path}/libTransforms.so" 
    # -extract-functions 
    if checked_functions_str:
        checked_functions = checked_functions_str.split(',')
        checked_functions_path = os.path.join(build_dir, 'checked_functions.txt')
        with open(checked_functions_path, 'w') as f:
            f.write('\n'.join(checked_functions))
        filter_cmd = ['-filter-file', checked_functions_path]
    else:
        filter_cmd = []
    # cmd = '{opt} -load "{util}" -load "{sc_build}/lib/libSCPass.so" -strip-debug -unreachableblockelim -globaldce -use-other-functions -sc -connectivity={con} -dump-checkers-network="{checker_network}" -patch-guide="{build_dir}/patch_guide.txt" -dump-sc-stat="{build_dir}/sc.stats" -checker-bitcode={checker} {filter_cmd} -o "{out}" "{src}"'.format(
    #         opt=OPT, indep_path=INPUTDEP_PATH, util=UTILLIB, sc_build=SC_BUILD,
    #         con=connectivity, build_dir=build_dir, src=source_bc, out=checked_bc,
    #         checker=checker_bc, filter_cmd=filter_cmd,
    #         checker_network=checker_network_path)
    patch_guide_path = '{}/patch_guide.txt'.format(build_dir)
    cmd = [
        OPT,
        '-load', UTILLIB,
        '-load', '{}/lib/libSCPass.so'.format(SC_BUILD),
        '-strip-debug', '-unreachableblockelim', '-globaldce',
        '-use-other-functions', '-sc', '-connectivity={}'.format(connectivity),
        '-dump-checkers-network', '{}/network_file'.format(build_dir),
        '-patch-guide', patch_guide_path,
        '-dump-sc-stat', '{}/sc.stats'.format(build_dir),
        '-checker-bitcode', checker_bc,
        '-o', checked_bc,
        source_bc,
        # using O3 directly somehow leads to opt crashing
        # therefore we call opt with just O3 after adding the self-checking
        # '-O3'
    ]
    if filter_cmd:
        cmd.extend(filter_cmd)

    # run the command
    if not run_cmd(cmd):
        print("apply_selfchecking failed:\n   {}".format(cmd))
        return False
    # run optimizations
    checked_optimized_bc, ext = os.path.splitext(checked_bc)
    checked_optimized_bc = checked_optimized_bc + "_opt" + ext
    if not run_cmd([OPT, '-O1', checked_bc, '-o', checked_optimized_bc]):
        print("apply_selfchecking optimization failed")
        return False
    checked_bc = checked_optimized_bc
    
    # read the patch guide and get all of the functions containing checkers
    with open(patch_guide_path, 'r') as f:
        patches = f.readlines()
    
    checker_functions = []
    for patch in patches:
        # patch has the format
        # checkerFunction, checkedFunction, placeholder1, placeholder2, placeholder3
        func_name = patch.partition(',')[0]
        checker_functions.append(func_name)

    # write them to a file so they can be consumed by the FilterFunctionPass
    # to whitelist them for obfuscations
    with open(checker_functions_path, 'w') as f:
        f.write('\n'.join(checker_functions))

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

def obfuscate_bc(obfuscations, build_dir, checker_bc, checker_functions_path):
    ollvm_bin = os.path.join(SC_HOME, 'obfuscation/Obfuscator-LLVM/build/bin')
    scvirt_opt = os.path.join(SC_HOME, 'obfuscation/sc-virt-master/build/bin/opt')
    scvirt_lib = os.path.join(SC_HOME, 'obfuscation/sc-virt-master/build/lib/LLVMScVirt.so')

    # no obfuscations specified, no need to obfuscate
    if not obfuscations:
        return checker_bc
    
    # scvirt,opaque,indir,scvirt
    # => [[scvirt], [opaque, indir], [scvirt]]
    log_dir = os.path.join(build_dir, 'obfuscate_bc.log')
    bc_input = checker_bc
    checker_bc = os.path.join(build_dir, 'checker_obf.bc')
    with open(log_dir, 'w') as log_dir_f:
        # since scvirt/ollvm use opt/clang, apply every transformation
        # individually (slower but easier. should be using the same in the end)
        for obf in obfuscations:
            obf_dissected = obf.split('.')
            if len(obf_dissected) > 1:
                assert(len(obf_dissected) == 2)
                coverage = int(obf_dissected[1])
            else:
                coverage = 10
            obf = obf_dissected[0]


            # check for ollvm obfuscations
            if obf in ollvm_options or obf == 'none':
                # TODO: check whether subst obfuscation is working, i.e. what it even does
                transforms = [] if obf == 'none' else [ollvm_options[obf]['pass_name']]
                coverages = [] if obf == 'none' else [ollvm_options[obf]['coverage_name'],
                    str(round(float(coverage)/100, 2))]
                cmd = [os.path.join(ollvm_bin, 'opt'),
                    '-o', checker_bc,
                    # '-c', '-emit-llvm',
                    '-filter-file', checker_functions_path,
                    bc_input,
                ]
                if obf == 'indir':
                    cmd.append('-cfg-indirect-reg2mem')
                cmd.extend(transforms)
                cmd.extend(coverages)
                print('running {} > {}'.format(' '.join(cmd), log_dir))
                log_dir_f.write('obfuscation: {}\n'.format(obf))
                success = run_cmd(cmd, log_dir_f)
                if not success:
                    print('obfuscate_bc failed')
                    return False
                bc_input = checker_bc
            elif obf in scvirt_options:
                cmd = [ scvirt_opt,
                    '-o', checker_bc,
                    '-load', scvirt_lib,
                    scvirt_options[obf]['pass_name'],
                    '-dump-file', os.path.join(build_dir, 'scvirt_stats.txt'),
                    '-filter-file', checker_functions_path,
                    bc_input
                ]
                print('running {} > {}'.format(' '.join(cmd), log_dir))
                log_dir_f.write('obfuscation: {}\n'.format(obf))
                success = run_cmd(cmd, log_dir_f)
                if not success:
                    print('obfuscate_bc failed')
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
    cmd = "{linker} {source_file} -o {out}".format(linker=CLANGPP if args.compile_cpp else CLANG, source_file=checked_bc, out=args.output)
    if args.link_args:
        cmd += ' {}'.format(args.link_args)
    if args.verbose:
        print(cmd)
    if not run_cmd(cmd):
        print('link failed:\n   {}'.format(cmd))
        return False

    return args.output

def patch_binary_r2(args, build_dir, out_file):
    dump_args = '"{out_file}" --patch-guide="{build_dir}/patch_guide.txt" --patch-dump="{build_dir}/patches.txt" --sc-stats="{build_dir}/sc.stats" -v'.format(out_file=out_file, build_dir=build_dir)
    if args.verbose:
        print('patch_binary, args to dump_pipe: {}'.format(dump_args))
    if not dump_main(shlex.split(dump_args)):
        print('patch_binary failed')
        return False
    return True

def patch_binary_ghidra(args, build_dir, out_file):
    patch_path = os.path.join(build_dir, 'patches.json')
    dump_args = '"{out_file}" --patch-guide="{build_dir}/patch_guide.txt" --patch-dump="{patch_path}" --sc-stats="{build_dir}/sc.stats" -v'.format(out_file=out_file, build_dir=build_dir, patch_path=patch_path)
    ghidra_cmd = [
        ghidra_headless,
        build_dir,     # project location
        'tmp_project', # project name
        '-noanalysis',
        '-import', out_file,
        '-postscript', ghidra_dump_path,
        dump_args
    ]
    if args.verbose:
        print('patch_binary, args to launch ghidra: {}'.format(ghidra_cmd))
    
    if not run_cmd(ghidra_cmd):
        print('patch_binary failed')
        return False
    
    if args.verbose:
        print('[*] patching binary with radare2')
    # current workaround since ghidra breaks the headers when exporting a binary
    # so use r2 for applying the patches
    with open(patch_path, 'r') as f:
        patches = json.load(f)

    import r2pipe
    r2 = r2pipe.open(out_file, ['-w'])
    for patch in patches:
        for patch_type in ('hash', 'size', 'hashtarget'):
            patch_str = 'wx {} @ {:#x}'.format(patch['patch_{}_data'.format(patch_type)],
                patch['patch_{}_addr'.format(patch_type)])
            if args.verbose:
                print('r2 execute: {}'.format(patch_str))
            r2.cmd(patch_str)
    r2.quit()
    
    return True

def run(args, build_dir):
    # if args.verbose:
    #     print('[*] obfuscate_checker_src')
    # checker_file = obfuscate_checker_src(args.obfuscation, build_dir)
    # if not checker_file:
    #     print('[-] obfuscate_checker_src')
    #     return False

    # if we shall only patch a binary we have to copy it first
    if args.patch_only:
        shutil.copyfile(args.source_file, args.output)
        out_file = args.output
    else:
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
            print('[*] apply_selfchecking')

        checker_functions_path = '{}/checker_functions.txt'.format(build_dir)
        checked_bc = apply_selfchecking(args.connectivity, build_dir, source_bc,
            checker_bc, args.checked_functions, checker_functions_path)
        if not checked_bc:
            print('[-] apply_selfchecking')
            return False

        if args.verbose:
            print('[*] obfuscate_program_bc')
        obf_checked_bc = obfuscate_bc(args.obfuscation, build_dir, checked_bc, checker_functions_path)
        if not obf_checked_bc:
            print('[-] obfuscate_program_bc')
            return False

        if args.verbose:
            print('[*] link')
        if args.to_bitcode:
            shutil.copyfile(obf_checked_bc, args.output)
            print('[*] --to-bitcode specified, skipping link + patching')
            print('[*] to patch the file after manually linking:')
            print('    {} --patch-only --build-dir "{build_dir}"'.format(__file__, build_dir=build_dir))
            return True
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
    if not patch_binary_ghidra(args, build_dir, out_file):
        print('[-] patch_binary')
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
