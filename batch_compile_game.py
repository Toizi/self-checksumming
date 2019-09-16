#!/usr/bin/env python

# sequence diagram
# https://sequencediagram.org/index.html#initialData=C4S2BsFMAICMENgGMAW0kHsC2AHE4QA7Ac2mEgGdhocAnDY2+LCgKFfiWA1ugAV6jZlki0OXEADdEMAQyZYRYuUMWiAtAD4EyFAH1MufJAB0OAJ4AuWgFdCACgywAZjYpJEIDIQoAaaEQ4NsB6ACYgtACU4qDS5HCIqAbYeFBm5qw6SYapphZaWfo5xumWmOBQXHoUGDa0SJT2gcFhEdGs4BgYONBOru6e3mycsTLQtoTVSOmZiUUpJfmaE1OlSLSQMnp0GA0UFI4ubh6gQ+0r7ulaF9MWZQtQ1bX1kHrcerBI9tE3V8t2qzu8BwOHA5mqkHAzlQkCQAGsiMRvqxfktUVY+sctjD4aJkejrgDLndio8cXDRG8MB8vj8ibdzITJsSrARCHCDChYRTaHp4IRQk86g18fS-ujLDg5h8iPBaOZkbNdMkjGkLAAedTqCU7chcSChaAAamgFEhznU5MRcFl8tYoU2EjiMHRrEgAtYKgUSk16kKKtypQ2wDqhHtjtG8X9pLyGQdIykMngznIvC9wlEQA

from __future__ import print_function
from glob import glob
import os
import argparse
from pprint import pprint
import subprocess
import shlex
import traceback
from multiprocessing.dummy import Pool
from multiprocessing import cpu_count

def run_cmd(cmd, cwd=None):
    try:
        subprocess.check_call(shlex.split(cmd), cwd=cwd)#, stdout=subprocess.STDOUT, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return cmd
    return True

games = {
    'sauerbraten': {
        'link_args': '--link-args="-O3 -fomit-frame-pointer -Wall -fsigned-char -fno-exceptions -fno-rtti -Lenet/.libs -lenet -L/usr/X11R6/lib -lX11 -L/usr/lib/x86_64-linux-gnu -lSDL -lSDL_image -lSDL_mixer -lz -lGL -lrt"',
        'rel_bc_path': 'sauer_client.bc',
        'protected_func_arg': '--checked-functions=_ZN4game5shootEP6fpsentRK3vec',
    },
    'crispy-doom': {
        'link_args': '--link-args="-DNDEBUG src/doom/libdoom.a /usr/lib/x86_64-linux-gnu/libSDL2main.a /usr/lib/x86_64-linux-gnu/libSDL2.so /usr/lib/x86_64-linux-gnu/libSDL2_mixer.so /usr/lib/x86_64-linux-gnu/libSDL2_net.so textscreen/libtextscreen.a pcsound/libpcsound.a opl/libopl.a /usr/lib/x86_64-linux-gnu/libpng.so -lm /usr/lib/x86_64-linux-gnu/libSDL2_mixer.so /usr/lib/x86_64-linux-gnu/libSDL2.so /usr/lib/x86_64-linux-gnu/libz.so"',
        'rel_bc_path': 'src/crispy-doom.bc',
        'protected_func_arg': '--checked-functions=A_FirePistol',
    },
}

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("-ob", "--obfuscation", help="list of obfuscations",
                        action='append', required=True)
    parser.add_argument("-j", "--process-count", type=int)
    parser.add_argument("--print-only", action="store_true",
        help="only print the commands to compile but do not execute them")
    parser.add_argument("-g", "--game", help="the game to compile", type=str,
        choices=(games.keys()), required=True)
    parser.add_argument("--seeds", help="comma separated list of seeds to use",
        type=str, default="1", required=False)
    parser.add_argument("-con", "--connectivity",
        help="desired connectiviy of the checkers network",
        type=int, default=10)
    parser.add_argument("input_dir", help="src directory of sauerbraten", type=str)

    args = parser.parse_args(argv)

    # parallel run by default
    if args.process_count is None:
        args.process_count = cpu_count() // 2

    # create output dir from input dir if no output was specified
    if not args.output:
        parent_dir, dir_name = os.path.split(os.path.abspath(args.input_dir))
        args.output = os.path.join(parent_dir, dir_name + '_bin')
    args.output = os.path.abspath(args.output)

    # make sure directory ends with separator to allow globbing
    if args.input_dir[-1] != os.path.sep:
        args.input_dir += os.path.sep
    
    args.seeds = [int(s) for s in args.seeds.split(',')]

    return args

def main(argv):
    args = parse_args(argv)
    if args.verbose:
        print('obfuscations: {}'.format(args.obfuscation))

    # dict that holds information about the game
    game_info = games[args.game]

    mydir   = os.path.dirname(os.path.abspath(__file__))
    run_sc  = os.path.join(mydir, 'run_sc.py')
    cmds = []

    print('[*] creating output dir {}'.format(args.output))
    os.mkdir(args.output)

    for seed in args.seeds:
        seed_dir = os.path.join(args.output, 'seed_{}'.format(seed))
        if args.verbose:
            print('[*] seed dir: {}'.format(seed_dir))
        if not os.path.exists(seed_dir):
            os.mkdir(seed_dir)
        # build all of the commands for the specified obfuscations
        for obf in args.obfuscation:
            obfuscations = obf.split(',')
            # generate obfuscation string
            obf_str = ' '.join(["--obfuscation {}".format(o) for o in obfuscations])
            # generate output filename
            out_fname_id = '-'.join(obfuscations)

            fpath = os.path.abspath(os.path.join(args.input_dir, game_info['rel_bc_path']))
            # get output name
            out_name, _ = os.path.splitext(os.path.basename(fpath))
            # extension is only requried on windows
            ext = '.exe' if os.name == 'nt' else ''
            out_name = '{}+{}{}'.format(out_name, out_fname_id, ext)
            out_path = os.path.join(seed_dir, seed_dir, out_name)
            cmd = '"{run}" {obf} "{source}" {link_args} --compile-bc -cpp --connectivity={conn} {protected_func_arg} --seed={seed} -o "{out}"'.format(
                run=run_sc, obf=obf_str, source=fpath, out=out_path,
                link_args=game_info['link_args'],
                protected_func_arg=game_info['protected_func_arg'],
                conn=args.connectivity,
                seed=seed)
            cmds.append(cmd)
    if args.verbose:
        pprint(cmds)

    pool = Pool(args.process_count)
    futures = []

    # go through all commands and launch them in parallel (thread pool)
    for cmd in cmds:
        if args.verbose or args.print_only:
            print('running (with working dir {}) {}'.format(cmd, args.input_dir))
        if not args.print_only:
            futures.append(pool.apply_async(run_cmd, (cmd, args.input_dir)))
            # if not run_cmd(cmd, args.input_dir):
            #     failed_cmds.append(cmd)

    pool.close()
    pool.join()
    
    failed_cmds = []
    # collect the results, i.e. whether a command failed
    for future in futures:
        result = future.get()
        if result is True:
            continue
        
        failed_cmds.append(result)
    
    # print any failed commands
    if failed_cmds:
        print('[-] {} command(s) failed'.format(len(failed_cmds)))
        for failed_cmd in failed_cmds:
            print(failed_cmd)
        return False

    print('[{}] Done'.format('-' if failed_cmds else '+'))
    return True

if __name__ == '__main__':
    main(os.sys.argv[1:])