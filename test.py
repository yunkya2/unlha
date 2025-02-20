import argparse
import datetime
import filecmp
import os
import random

import unlha

METHODS = {
    'lh0': '-z',
    'lh1': '-o',
    'lh5': '-o5',
    'lh6': '-o6',
    'lh7': '-o7',
}

def run(args):
    now_str = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    random_dir = os.path.join(args.output, 'random')
    decompressed_dir = os.path.join(args.output, 'decompressed', args.method)
    os.makedirs(random_dir, exist_ok=True)
    os.makedirs(decompressed_dir, exist_ok=True)
    filesize = random.randint(1_000_000, 6_000_000)
    print(f'filesize = {filesize}')
    random_ascii_data = bytes(random.randint(' ', '~') for _ in range(filesize))
    random_filename_basename = f'rand_{now_str}.rand'
    random_filename = os.path.join(random_dir, random_filename_basename)
    print(f'random_filename = {random_filename}')
    with open(random_filename, 'wb') as f:
        f.write(random_ascii_data)
    compressed_filename = os.path.join(random_dir, f'{random_filename}.{args.method}')
    cmd = f'{args.lha} c {METHODS[args.method]} {compressed_filename} {random_filename_basename}'
    print(f'cmd: {cmd}')
    test_cmd = f'{args.lha} t {compressed_filename}'
    print(f'test_cmd: {test_cmd}')
    print(f'xxd {compressed_filename}|less')
    os.chdir(random_dir)
    ret = os.system(cmd)
    if ret != os.EX_OK:
        print(f'Command {cmd} failed, ret {ret}')
        return
    os.chdir(decompressed_dir)
    with open(compressed_filename, 'rb') as fh:
        unlha.unlha(fh, unlha.UNLHA_EXTRACT, [])
    decompressed_filename = os.path.join(decompressed_dir, random_filename_basename)
    if filecmp.cmp(random_filename, decompressed_filename, shallow=False):
        print(f'Files {random_filename} and {decompressed_filename} are identical, removing...')
        os.remove(compressed_filename)
        os.remove(random_filename)
        os.remove(decompressed_filename)
    else:
        print(f'Files {random_filename} and {decompressed_filename} are different')

parser = argparse.ArgumentParser()
parser.add_argument("--lha", action='store', required=False, default='lha')
parser.add_argument("--loop", action='store_true', required=False)
parser.add_argument("--method", action='store', required=True, choices=METHODS.keys())
parser.add_argument("--output", action='store', required=False, default='/tmp/unlha')
args = parser.parse_args()

while True:
    run(args)
    if not args.loop:
        break
