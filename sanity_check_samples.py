#!/usr/bin/env python3
"""
Script to check whether compiled mibench samples are stable.
This is useful since some of the obfuscations introduce segfaults or no checker is triggered.
To use this, simply compile samples with the batch_compile_mibench.py script and use this
script on the output directory. For quick testing, only specify virtualization and none as obfuscations
and run the script. If no error occurs, rerun with all of the obfuscations you want and make sure
there are still no errors. Otherwise, simply change the seed and try again (batch compilation supports
specifying multiple seeds at once).
This way you can check the most frequent issues (virtualization creating segfaults and no checkers in
the code path) quickly.
"""

from glob import glob
import os
import json
import tempfile
import shutil
import subprocess
import time
import shlex
import re
from threading import Timer, active_count
from pprint import pprint

import sys

def main():
    try:
        input_dir = os.sys.argv[1]
    except:
        print(f'Usage: {__file__} samples_dir')
        exit(1)
    
    mydir = os.path.dirname(os.path.abspath(__file__))
    sys.path.append(os.path.join(mydir, '../taint'))

    from r2_apply_patches import crack_function

    # make sure globbing works
    if input_dir[-1] != os.path.sep:
        input_dir = input_dir + '/' 
    
    # hardcode cmdline json file for now
    cmdline_path = os.path.join(mydir, 'samples/cmdline-args/cmdline.json')
    cmdline_dir = os.path.join(mydir, 'samples/cmdline-args/')

    with open(cmdline_path, 'r') as f:
        cmd_infos = json.load(f)

    build_dir = tempfile.mkdtemp()
    # glob samples
    samples = glob(f'{input_dir}*+*')
    commands = []
    for sample in samples:
        base_name = os.path.basename(sample)
        org_name, _, obf_str = base_name.partition('+')

        # get relevant cmd info
        cmd_info = cmd_infos.get(org_name)
        if cmd_info is None:
            print(f'[*] could not find cmd info for {base_name}')
            continue
    
        # build environment for command
        cmd_dir = os.path.join(build_dir, base_name)
        os.mkdir(cmd_dir)

        # create symlink to this directory
        os.symlink(os.path.abspath(sample), os.path.join(cmd_dir, 'bin'))

        # create tampered binary
        tampered_path = os.path.join(cmd_dir, 'bin_tampered')
        shutil.copy(sample, os.path.join(cmd_dir, 'bin_tampered'))
        crack_function(tampered_path, 'mibench_dummy', check_func_exists=False)

        # copy required files to directory
        for required_file in cmd_info['required_files']:
            shutil.copy(os.path.join(cmdline_dir, required_file), cmd_dir)
        
        cmd = ['./bin']
        if cmd_info['args']:
            cmd.extend(cmd_info['args'])
        
        commands.append((cmd, cmd_dir, cmd_info.get('success_exit_code', 0)))

        # write it to file for easier debugging
        with open(os.path.join(cmd_dir, 'run.sh'), 'w') as f:
            f.write('#!/bin/bash\n')
            f.write(' '.join((f"'{c}'" for c in cmd)))
            f.write('\n')
        
    def worker(cmd, cmd_dir, expected_exit_code):
        if True:
            print(f'running {cmd_dir}')

        # shell=True requires a string as argument
        cmd_str = ' '.join(cmd)
        ret = subprocess.run(cmd_str, cwd=cmd_dir, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = ret.stdout.decode('utf-8', 'ignore')
        if ret.returncode != expected_exit_code:
            print(f'[-] error running {cmd_dir}')
            print(f'  {cmd_str}')
            print(output)
            return

        # check that they contain at least one checker
        cmd_str = ['./bin_tampered']
        cmd_str.extend(cmd[1:])
        cmd_str = ' '.join(cmd_str)
        ret = subprocess.run(cmd_str, cwd=cmd_dir, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = ret.stdout.decode('utf-8', 'ignore')
        if ret.returncode != expected_exit_code:
            print(f'[-] error running {cmd_dir}')
            print(f'  {cmd_str}')
            print(output)
            return
        
        for match in re.finditer(r'Tampered binary \(id = (\d+)\)', output):
            break
        else:
            print(f'[-] no tamper detected for {cmd_dir}')

        
    # run the commands
    for command in commands:
        # Timer(0, worker, args=command).start()
        worker(*command)
    

    
    # while active_count() > 1:
    #     print(f'active count: {active_count()}')
    #     time.sleep(5)
    print('done')


if __name__ == "__main__":
    main()
