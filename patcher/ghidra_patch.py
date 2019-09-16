#!/usr/bin/env python
from __future__ import print_function
import sys
import struct
import os
import base64
import os.path
import json
from pprint import pprint
import argparse
from binascii import hexlify
import shlex

def dump_debug_info(*args):
    if debug_mode:
        text = ""
        for arg in args:
            text+=arg
        print(text)

def precompute_hash(offset, size):
    dump_debug_info( 'Precomputing hash')
    func_bytes = bytearray(getBytes(toAddr(offset), size))
    h = 0
    for b in func_bytes:
        h = h ^ b
    dump_debug_info('hash: {:x}'.format(h))
    return h

def find_placeholder_sequential(mm,start_index,struct_flag, search_value):
    search_bytes = struct.pack(struct_flag, search_value)
    addr = mm.find(search_bytes,start_index)
    return addr

def find_placeholder(struct_flag, func, search_value):
    # # flat api call
    # # build a search string for findBytes
    # # 0x1337 => r'\x13\x37'
    # hex_val = hexlify(struct.pack(struct_flag, search_value))
    # search_str = ''.join(['\\x' + hex_val[i:i+2] for i in range(0, len(hex_val), 2)])
    # addr = findBytes(func.getBody(), search_str, 1, 1)
    # if not addr:
    #     return None
    # return addr[0].getOffset()

    # full api call
    search_val = struct.pack(struct_flag, search_value)
    addr = currentProgram.memory.findBytes(func.getEntryPoint(),
        toAddr(func.getEntryPoint().getOffset() + get_function_size(func) - 1),
        bytes(search_val), None, True, None)
    if not addr:
        return None
    return addr.getOffset()

def patch_address(addr, patch_value):
    instr = getInstructionContaining(toAddr(addr))
    if instr:
        instr_addr = instr.getAddress()
        clearListing(instr_addr)

    setBytes(toAddr(addr), patch_value)

    if instr:
        disassemble(instr_addr)

def find_address_of_placeholders(patch, checker_function):
    for placeholder in ('hashaddr_placeholder', 'hash_placeholder', 'size_placeholder'):#patch:
        struct_flag = '<I'
        address = -1

        placeholder_value = patch[placeholder]

        address = find_placeholder(struct_flag, checker_function, placeholder_value)
        if address is None: 
            dump_debug_info("ERR. Failed to find placeholder {} in function {} in the binary".format(
                placeholder_value, checker_function.getName()))
            return False

        patch[placeholder.replace('placeholder', 'address')] = address

    return True

def find_all_placeholders(guard_patches):
    placeholder_addresses = {}
    for patch in guard_patches:
        for placeholder in ('hashaddr_placeholder', 'hash_placeholder', 'size_placeholder'):#patch:
            struct_flag = '<I'
            address = -1

            placeholder_value = patch[placeholder]

            address = find_placeholder(struct_flag, patch['checker_function'], placeholder_value)
            if address is None: 
                dump_debug_info("ERR. Failed to find placeholder {} in the binary".format(placeholder_value))
                return False

            if placeholder_value not in placeholder_addresses:
                placeholder_addresses[placeholder_value] = address

    return placeholder_addresses


def patch_placeholder(struct_flag, addr_to_patch, target_value, patch, name_to_insert):
    num_patches_applied = 0
    #addr = find_placeholder(mm,struct_flag,placeholder_value)
    addr_to_patch = patch[addr_to_patch]
    target_value = patch[target_value]

    patch_bytes = struct.pack(struct_flag, target_value)
    # put actual patch values into patches
    if name_to_insert:
        patch['patch_{}_addr'.format(name_to_insert)] = addr_to_patch
        patch['patch_{}_data'.format(name_to_insert)] = hexlify(patch_bytes).decode('ascii')

    patch_address(addr_to_patch, patch_bytes)
    # dump_debug_info( 'Patched {} with {}'.format(placeholder_value, target_value))
    num_patches_applied +=1

    return num_patches_applied


function_cache = {}
def find_function(func_name):
    global function_cache

    # see if it's cached first
    func = function_cache.get(func_name)
    if func:
        return func

    # use regular getFunction
    func = getFunction(func_name)
    if func:
        function_cache[func_name] = func
        return func
    
    
    # in case of mangled names e.g. getFunction does not find it
    # therefore we check if a symbol with that name exists
    sym = getSymbol(func_name, None)
    if sym is None:
        function_cache[func_name] = None
        return None

    func = getFunctionAt(sym.getAddress())
    function_cache[func_name] = func

    return func

def get_function_size(func):
    # TODO: since disassembly might fail through obfuscation and therefore
    # the function might only contain some of the basic blocks at the beginning,
    # add the option to compute the size by
    # getFunctionAfter().getEntryPoint() - getMinAddress()
    # this assumes that all functions are laid out linearly and not thunked

    # # old and "correct" code
    # body = func.getBody()
    # return body.getMaxAddress().getOffset() - body.getMinAddress().getOffset()
    next_func = getFunctionAfter(func)
    return next_func.getEntryPoint().getOffset() - func.getBody().getMinAddress().getOffset()

def get_patches(input_file, guide_content):
        
    patches = []
    for c in guide_content:
        s = c.split(',')
        checker_func_name = s[0]
        target_func_name = s[1]
        hashaddr_placeholder = int(s[2])
        size_placeholder = int(s[3])
        hash_placeholder = int(s[4])

        
        target_func = find_function(target_func_name)
        checker_func = find_function(checker_func_name)

        if target_func and checker_func:
            patch = {
                'hashaddr_placeholder': hashaddr_placeholder, 
                'hashaddr_address': 0, # address of the hash
                'size_placeholder': size_placeholder, 
                'size_address': 0, # address of the length that should be hashed
                'hash_placeholder': hash_placeholder,
                'hash_address': 0, # address of the hash value
                'checkee_addr' : target_func.getEntryPoint().getOffset(), # address of the function that will be hashes
                'checker_function' : checker_func.getName(), # name of the function that contains the check
                'size_target': get_function_size(target_func), # how many bytes should be hashed
                'expected_hash': 0,
                'dummy': False
            }
            if not find_address_of_placeholders(patch, checker_func):
                print('ERR: find_address_of_placeholders failed')
            patches.append(patch)
        else:
            # pprint(funcs)
            print('ERR: failed to find function:{}'.format(target_func))
            return False
    if len(patches) != len(guide_content):
        print('ERR: len (patches) != len( guide) {}!={}'.format(len(patches),len(guide_content)))
        return False
    return patches

def apply_patches(input_file, patches, patch_dump_file):
    # open hex editor
    # every line contains information about 3 patches,
    # size, address and hash that needs to be patched
    total_patches = 0
    expected_patches = len(patches) * 3
    dump_debug_info("patches {}".format(patches))

    # # find addresses before starting to patch
    # addresses = find_all_placeholders(patches)
    # if not addresses:
    #     return False

    dump_patch = []
    for patch in patches:
        address_patch = patch_placeholder('<I', 'hashaddr_address', 'checkee_addr', patch, 'hash')
        total_patches += address_patch
        if address_patch == 0:
            dump_debug_info( "can't patch address")

        size_patch = patch_placeholder('<I', 'size_address', 'size_target', patch, 'size')
        total_patches += size_patch
        if not size_patch:
            dump_debug_info( "can't patch size")


        expected_hash = precompute_hash(patch['checkee_addr'], patch['size_target'])
        if patch['dummy']:
            expected_hash = 0

        patch['expected_hash'] = expected_hash
        hash_patch = patch_placeholder('<I', 'hash_address', 'expected_hash', patch, 'hashtarget')
        total_patches += hash_patch
        if not hash_patch:
            dump_debug_info( "can't patch hash")


        if not size_patch or not address_patch or not hash_patch:
            print('Failed to find size and/or address and/or hash patches')
            return False
        dump_patch.append(patch)
        dump_debug_info( 'expected patches:{}, total patched:{}'.format(expected_patches, total_patches))
    if total_patches != expected_patches:
        print('Failed to patch all expected patches:', expected_patches, ' total patched:', total_patches)
    else:
        print('Successfuly patched all {} placeholders'.format(total_patches))
    if patch_dump_file:
        with open(patch_dump_file, 'w') as outfile:
            json.dump(dump_patch, outfile)

    return True

def patches_required(sc_stats_file):
    # We should not seek for patch guide when stats indicate no guards, see #42
    if sc_stats_file:
        with open(sc_stats_file, 'r') as f:
            sc_stats = json.load(f)
        if sc_stats["numberOfGuards"] == 0:
            print('SC stats indicates there is nothing to be patched')
            return False
    return True


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-pg", "--patch-guide", required=True,
                        type=str,
                        help="patch guide input file")
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-s", "--sc-stats", help="the self-checking stats file")
    parser.add_argument("-p", "--patch-dump", help="file where the patches will be written")
    parser.add_argument("input_binary", help="input binary that will be patched")
    parser.add_argument("-o", "--output", help="output path, NYI", required=False)
    args = parser.parse_args(argv)
    
    global debug_mode
    debug_mode = args.verbose is True
    return args

def main(argv):
    println("ghidra_patch.py got args:\n   {}".format(argv))
    args = parse_args(argv)

    if not patches_required(args.sc_stats):
        return True

    # open patch guide
    if not os.path.exists(args.patch_guide):
        print('ERR. patch guide file cannot be found!')
        return False

    with open(args.patch_guide) as f: 
        guide_content = f.readlines()
    guide_content = [x.strip() for x in guide_content]
    dump_debug_info( 'content: {}'.format(guide_content))

    patches = get_patches(args.input_binary, guide_content)
    if not patches:
        print("[-] get_patches failed")
        return False

    if not apply_patches(args.input_binary, patches, args.patch_dump):
        print('[-] apply_patches failed')
        return False

    return True


if __name__ == '__main__':
    args = []
    for arg in getScriptArgs():
        args.extend(shlex.split(arg))
    main(args)