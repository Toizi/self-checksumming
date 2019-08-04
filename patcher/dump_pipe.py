#!/usr/bin/env python
from __future__ import print_function
import r2pipe
import sys
import struct
import mmap
import os
import base64
import os.path
import json
from pprint import pprint
import argparse

def dump_debug_info(*args):
    if debug_mode:
        text = ""
        for arg in args:
            text+=arg
        print(text)

def precompute_hash(r2, offset, size):
    dump_debug_info( 'Precomputing hash')
    h = 0
    dump_debug_info( "p6e {}@{}".format(size,offset))
    b64_func = r2.cmd("p6e {}@{}".format(size,offset))
    func_bytes = bytearray(base64.b64decode(b64_func))
    for b in func_bytes:
        #sys.stdout.write("%x "%b)
        h = h ^ b
    dump_debug_info(  'hash:',hex(h)) 
    return h

def find_placeholder_sequential(mm,start_index,struct_flag, search_value):
    search_bytes = struct.pack(struct_flag, search_value)
    addr = mm.find(search_bytes,start_index)
    return addr

def find_placeholder(mm,struct_flag,search_value):
    search_bytes = struct.pack(struct_flag, search_value)
    addr = mm.find(search_bytes)
    if addr == -1:
        mm.seek(0)
    addr = mm.find(search_bytes)
    return addr

def patch_address(mm, addr, patch_value):
    mm.seek(addr,os.SEEK_SET)
    mm.write(patch_value)

def find_all_placeholders(mm,guard_patches):
    placeholder_addresses = {}
    for patch in guard_patches:
        for placeholder in patch:
            struct_flag = ''
            address = -1
            if placeholder == 'add_placeholder' or placeholder == 'hash_placeholder':
                struct_flag = '<I'
            elif placeholder == 'size_placeholder':
                struct_flag = '<I'
            if struct_flag!='':
                placeholder_value = patch[placeholder]
                address = find_placeholder(mm, struct_flag, placeholder_value)
                if placeholder_value not in placeholder_addresses:
                    placeholder_addresses[placeholder_value] = []   
                if address ==-1: 
                    dump_debug_info("ERR. Failed to find placeholder {} in the binary".format(placeholder_value))
                    return False
                while address!=-1:
                    placeholder_addresses[placeholder_value].append(address)
                    start_index = address+1 
                    address = find_placeholder_sequential(mm, start_index, struct_flag, placeholder_value)
                
    found_addresses = 0
    pmap ={}
    for paddress in placeholder_addresses:
        count_placeholders = len(placeholder_addresses[paddress])
        for address in placeholder_addresses[paddress]:
            if address in pmap:
                pholder = pmap[address] 
                if pholder != paddress: 
                    print("ERR. Same address mapped to two placehoders",pholder, paddress)
                    return False
        found_addresses =found_addresses + count_placeholders
    return placeholder_addresses


def patch_placeholder(mm, struct_flag,addresses, placeholder_value, target_value):
    num_patches_applied = 0
    #addr = find_placeholder(mm,struct_flag,placeholder_value)
    if placeholder_value not in addresses:
        print("Err. can't find placeholder in the addresses")
    for addr in addresses[placeholder_value]:
        patch_bytes = struct.pack(struct_flag, target_value)
        patch_address(mm,addr,patch_bytes)
        dump_debug_info( 'Patched {} with {}'.format(placeholder_value, target_value))
        num_patches_applied +=1

    return num_patches_applied


def get_patches(input_file, guide_content, r2):
    # find addresses and sizes of all functions
    function_list = r2.cmdj("aflj")
    funcs = {}
    for function in function_list:
        attr = {'size':function['size'], 'offset':function['offset']}
        funcs[function['name']] = attr
        
    patches = []
    for c in guide_content:
        s = c.split(',')
        target_func = s[0].rstrip('_')
        add_placeholder = int(s[1])
        size_placeholder = int(s[2])
        hash_placeholder = int(s[3])
        if target_func not in funcs:
            target_func = 'sym.' + target_func
        if target_func in funcs:
        #Compute expected hashes
            
            offset = funcs[target_func]['offset']
            size = funcs[target_func]['size']
            patch = {'add_placeholder':add_placeholder, 
                'size_placeholder':size_placeholder, 
                'hash_placeholder':hash_placeholder,
                'add_target' : offset,
                'size_target': size,
                'hash_target': 0 , 'dummy': False}
            patches.append(patch)
        else:
            # required due to r2 bug that seeks to wrong function
            # for some reason if af is not called before
            r2.cmd('af ' + target_func)
            r2.cmd('s ' + target_func)
            funcinfo = r2.cmdj('afij')
            if funcinfo:
                print('TAKING ME')
                print(funcinfo)
                func_info = funcinfo[0]
                error = False
                if target_func.replace('sym.','') != func_info['name'].replace('sym.',''):
                    if func_info['name'].replace('sym.', '') == 'entry0':
                        dump_debug_info('WARN: ignoring function mismatch entry0')
                    else:
                        print('ERR. Target function {} does not match {}'.format(target_func, func_info['name']))
                        error = True
                offset = func_info['offset']
                size = func_info['size']
                patch = {'add_placeholder': add_placeholder,
                        'size_placeholder': size_placeholder,
                        'hash_placeholder': hash_placeholder,
                        'add_target': offset,
                        'size_target': size,
                        'hash_target': 0, 'dummy':error}
                patches.append(patch)
            else:
                pprint(funcs)
                print('ERR: failed to find function:{}'.format(target_func))
                return False
    if len(patches) != len(guide_content):
        print('ERR: len (patches) != len( guide) {}!={}'.format(len(patches),len(guide_content)))
        return False
    return patches

def apply_patches(input_file, patches, patch_dump_file, r2):
    # open hex editor
    # every line contains information about 3 patches,
    # size, address and hash that needs to be patched
    total_patches = 0
    expected_patches = len(patches) * 3
    dump_debug_info("patches {}".format(patches))

    with open(input_file, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), 0)
            
        #find addresses before starting to patch
        addresses = find_all_placeholders(mm, patches)
        if not addresses:
            return False

        dump_patch = []
        for patch in patches:
            address_patch = patch_placeholder(mm,'<I', addresses, patch['add_placeholder'], patch['add_target']) 
            total_patches += address_patch
            if address_patch == 0:
                dump_debug_info( "can't patch address")
            size_target = patch['size_target']
            if patch['dummy']: 
                size_target = 0
            size_patch = patch_placeholder(mm,'<I', addresses, patch['size_placeholder'], size_target)
            total_patches += size_patch
            if not size_patch:
                dump_debug_info( "can't patch size")


            expected_hash = precompute_hash(r2, patch['add_target'], patch['size_target'])
            if patch['dummy']:
                expected_hash = 0

            patch['hash_target'] = expected_hash
            hash_patch = patch_placeholder(mm,'<I', addresses, patch['hash_placeholder'],expected_hash) 
            total_patches += hash_patch
            if not hash_patch:
                dump_debug_info( "can't patch hash")


            if not size_patch or not address_patch or not hash_patch:
                print('Failed to find size and/or address and/or hash patches')
                return False
            dump_patch.append(patch)
            dump_debug_info( 'expected patches:{}, total patched:{}'.format(expected_patches, total_patches))
        if total_patches != expected_patches:
            print('Failed to patch all expected patches:',expected_patches, ' total patched:',total_patches)
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

    r2 = r2pipe.open(args.input_binary)
    r2.cmd("aa")

    patches = get_patches(args.input_binary, guide_content, r2)
    if not patches:
        print("[-] get_patches failed")
        return False

    if not apply_patches(args.input_binary, patches, args.patch_dump, r2):
        print('[-] apply_patches failed')
        return False

    return True


if __name__ == '__main__':
    if not main(os.sys.argv[1:]):
        exit(1)