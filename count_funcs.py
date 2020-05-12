#!/usr/bin/env python3
"""
Counts how many functions are obfuscated for each module
"""

# command to use this script
# find mibench_build -wholename '*/virt*/obfuscate_bc.log' -exec ./count_funcs.py {} \; | sort

import os
import re

def main():
    fpath = os.sys.argv[1]
    with open(fpath, 'r') as f:
        lines = f.readlines()

    all_functions = []
    regex = re.compile(r'^Taking (.*)$')
    for line in lines:
        m = regex.search(line)
        if m is None:
            continue
        all_functions.append(m.group(1))

    name = os.path.dirname(fpath)
    print('{}: {}'.format(name, len(all_functions)))
    # print(all_functions)


if __name__ == '__main__':
    main()

