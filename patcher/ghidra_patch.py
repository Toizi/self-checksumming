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

# def find_placeholder(mm,struct_flag,search_value):
#     search_bytes = struct.pack(struct_flag, search_value)
#     addr = mm.find(search_bytes)
#     if addr == -1:
#         mm.seek(0)
#     addr = mm.find(search_bytes)
#     return addr
def find_placeholder(struct_flag, func, search_value):
    # build a search string for findBytes
    # 0x1337 => r'\x13\x37'
    hex_val = hexlify(struct.pack(struct_flag, search_value))
    search_str = ''.join(['\\x' + hex_val[i:i+2] for i in range(0, len(hex_val), 2)])

    addr = findBytes(func.getBody(), search_str, 1, 1)
    if not addr:
        return None
    return addr[0].getOffset()

def patch_address(addr, patch_value):
    instr = getInstructionContaining(toAddr(addr))
    instr_addr = instr.getAddress()
    clearListing(instr_addr)
    setBytes(toAddr(addr), patch_value)
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

            # while address is not None:
            #     placeholder_addresses[placeholder_value].append(address)
            #     start_index = address+1 
            #     address = find_placeholder_sequential(mm, start_index, struct_flag, placeholder_value)
                
    # found_addresses = 0
    # pmap = {}
    # for paddress in placeholder_addresses:
    #     count_placeholders = len(placeholder_addresses[paddress])
    #     for address in placeholder_addresses[paddress]:
    #         if address in pmap:
    #             pholder = pmap[address] 
    #             if pholder != paddress: 
    #                 print("ERR. Same address mapped to two placehoders", pholder, paddress)
    #                 return False
    #     found_addresses = found_addresses + count_placeholders
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


def get_patches(input_file, guide_content):
    # find addresses and sizes of all functions
    # function_list = r2.cmdj("aflj")
    # funcs = {}
    # for function in function_list:
    #     attr = {'size':function['size'], 'offset':function['offset']}
    #     funcs[function['name']] = attr
    funcs = {}
    func = getFirstFunction()
    while func is not None:
        body = func.getBody()
        size = body.getMaxAddress().getOffset() - body.getMinAddress().getOffset()
        funcs[func.getName()] = {
            'size': size,
            'offset': func.getEntryPoint().getOffset(),
            'function': func
            }
        func = getFunctionAfter(func)
        
    patches = []
    for c in guide_content:
        s = c.split(',')
        checker_func = s[0].rstrip('_')
        target_func = s[1].rstrip('_')
        hashaddr_placeholder = int(s[2])
        size_placeholder = int(s[3])
        hash_placeholder = int(s[4])

        if target_func in funcs and checker_func in funcs:
            offset = funcs[target_func]['offset']
            size = funcs[target_func]['size']
            patch = {'hashaddr_placeholder': hashaddr_placeholder, 
                'hashaddr_address': 0, # address of the hash
                'size_placeholder': size_placeholder, 
                'size_address': 0, # address of the length that should be hashed
                'hash_placeholder': hash_placeholder,
                'hash_address': 0, # address of the hash value
                'checkee_addr' : offset, # address of the function that will be hashes
                'checker_function' : funcs[checker_func]['function'].getName(), # name of the function that contains the check
                'size_target': size, # how many bytes should be hashed
                'expected_hash': 0,
                'dummy': False
            }
            if not find_address_of_placeholders(patch, funcs[checker_func]['function']):
                print('ERR: find_address_of_placeholders failed')
            patches.append(patch)

        # else:
        #     # required due to r2 bug that seeks to wrong function
        #     # for some reason if af is not called before
        #     r2.cmd('af ' + target_func)
        #     r2.cmd('s ' + target_func)
        #     funcinfo = r2.cmdj('afij')
        #     if funcinfo:
        #         print('TAKING ME')
        #         print(funcinfo)
        #         func_info = funcinfo[0]
        #         error = False
        #         if target_func.replace('sym.','') != func_info['name'].replace('sym.',''):
        #             if func_info['name'].replace('sym.', '') == 'entry0':
        #                 dump_debug_info('WARN: ignoring function mismatch entry0')
        #             else:
        #                 print('ERR. Target function {} does not match {}'.format(target_func, func_info['name']))
        #                 error = True
        #         offset = func_info['offset']
        #         size = func_info['size']
        #         patch = {'hashaddr_placeholder': hashaddr_placeholder,
        #                 'size_placeholder': size_placeholder,
        #                 'hash_placeholder': hash_placeholder,
        #                 'checkee_addr': offset,
        #                 'size_target': size,
        #                 'expected_hash': 0, 'dummy':error}
        #         patches.append(patch)
        else:
            pprint(funcs)
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

    # r2 = r2pipe.open(args.input_binary)
    # r2.cmd("aa")

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