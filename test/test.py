import os
import sys
import stat
import argparse
import glob
import shutil
import fnmatch
import time
import struct
import random
import pprint
import hashlib
from sys import platform

parser = argparse.ArgumentParser(description='Zip/unzip test script')
parser.add_argument('--exe_dir', help='Minizip command line tool directory', default=None, action='store', required=False)
parser.add_argument('--deflate', help='Runs zlib/deflate tests', action='store_const', const=True, default=None, required=False)
parser.add_argument('--raw', help='Runs raw tests', action='store_const', const=True, default=None, required=False)
parser.add_argument('--bzip2', help='Runs bzip2 tests', action='store_const', const=True, default=None, required=False)
parser.add_argument('--lzma', help='Runs lzma tests', action='store_const', const=True, default=None, required=False)
parser.add_argument('--pkcrypt', help='Runs pkware traditional encryption tests', action='store_const', const=True, default=None, required=False)
parser.add_argument('--wzaes', help='Runs winzip aes encryption tests', action='store_const', const=True, default=None, required=False)
parser.add_argument('--split', help='Runs disk span tests', action='store_const', const=True, default=None, required=False)
parser.add_argument('--zipcd', help='Runs zip/unzip central dir tests', action='store_const', const=True, default=None, required=False)
parser.add_argument('--sign', help='Runs signing tests', action='store_const', const=True, default=None, required=False)
parser.add_argument('--rand', help='Runs tests against random generated files', action='store_const', const=True, default=None, required=False)
args, unknown = parser.parse_known_args()

def hash_file_sha1(path):
    sha1 = hashlib.sha1()
    with open(path, 'rb') as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest()

def find_files(directory, pattern, recursive = True):
    if directory == '':
        directory = os.getcwd()
    if recursive:
        items = os.walk(directory)
    else:
        items = [next(os.walk(directory))]
    for root, dirs, files in items:
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename
    
def erase_file(path, retries = 10, sleep = 0.1):
    #print('Deleting {0}'.format(path))
    for i in range(retries):
        try:
            os.chmod(path, stat.S_IWUSR)
            os.remove(path)
        except WindowsError:
            time.sleep(sleep)
        else:
            break

def erase_files(search_pattern):
    search_dir, match = os.path.split(search_pattern)
    for path in find_files(search_dir, match):
        erase_file(path)

def erase_dir(path, retries = 10):
    if not os.path.exists(path):
        return
    #print('Erasing dir {0}'.format(path))
    # shutil.rmtree doesn't work well and sometimes can't delete
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            filename = os.path.join(root, name)
            erase_file(filename)
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(path)

def get_exec(name):
    global args
    if platform == 'win32':
        name += '.exe'
    if args.exe_dir is not None:
        return os.path.join(args.exe_dir, name)
    return name

def get_files_info(path):
    if os.path.isfile(path):
        return {
            path: {
                'hash': hash_file_sha1(path),
                'size': os.path.getsize(path)
            }
        }
    info = {}
    for root, dirs, files in os.walk(path):
        path = root.split(os.sep)
        for path in files:
            info.update(get_files_info(path))
    return info

def create_random_file(path, size):
    import numpy
    if os.path.exists(path):
        return
    with open(path, 'wb') as fout:
        i = 0
        while size > 0:
            if i == 0 or i % 400000 == 0:
                data = numpy.random.rand(100000)
            floatlist = numpy.squeeze(numpy.asarray(data))
            buf = struct.pack('%sf' % len(floatlist), *floatlist)
            fout.write(buf)
            size -= len(buf)
            i += 1

def zip(zip_file, zip_args, files):
    cmd = '{0} {1} {2} {3}'.format(get_exec('minizip'), zip_args, zip_file, ' '.join(files))
    print cmd
    err = os.system(cmd)
    if (err != 0):
        print('Zip returned error code {0}'.format(err))
        exit(err)

def list(zip_file):
    cmd = '{0} -l {1}'.format(get_exec('minizip'), zip_file)
    print cmd
    err = os.system(cmd)
    if (err != 0):
        print('List returned error code {0}'.format(err))
        exit(err)

def unzip(zip_file, dest_dir, unzip_args = ''):
    cmd = '{0} -x {1} -d {2} {3}'.format(get_exec('minizip'), unzip_args, dest_dir, zip_file)
    print cmd
    err = os.system(cmd)
    if (err != 0):
        print('Unzip returned error code {0}'.format(err))
        exit(err)

def zip_list_unzip(zip_file, dest_dir, zip_args, unzip_args, files):
    # Single test run
    original_infos = {}
    for (i, path) in enumerate(files):
        original_infos.update(get_files_info(path))

    erase_files(zip_file[0:-2] + "*")
    erase_dir(dest_dir)

    zip(zip_file, zip_args, files)
    list(zip_file)
    unzip(zip_file, dest_dir, unzip_args)

    new_infos = {}
    for (i, path) in enumerate(files):
        new_infos.update(get_files_info(path))

    if (' '.join(original_infos) != ' '.join(new_infos)):
        print('Infos do not match')
        print('Original: ')
        pprint(original_infos)
        print('New: ')
        print(new_infos)

def file_tests(method, zip_arg = '', unzip_arg = ''):
    global args
    print('Testing {0} on Single File'.format(method))
    zip_list_unzip('test.zip', 'out', zip_arg, unzip_arg, ['test.c'])
    print('Testing {0} on Two Files'.format(method))
    zip_list_unzip('test.zip', 'out', zip_arg, unzip_arg, ['test.c', 'test.h'])
    print('Testing {0} Directory'.format(method))
    zip_list_unzip('test.zip', 'out', zip_arg, unzip_arg, ['repo'])
    if args.rand:
        print('Testing {0} 1MB file'.format(method))
        create_random_file('1MB.dat', 1 * 1024 * 1024)
        zip_list_unzip('test.zip', 'out', zip_arg, unzip_arg, ['1MB.dat'])
        print('Testing {0} 25MB file'.format(method))
        create_random_file('25MB.dat', 25 * 1024 * 1024)
        zip_list_unzip('test.zip', 'out', zip_arg, unzip_arg, ['25MB.dat'])

def compression_method_tests(method = '', zip_arg = '', unzip_arg = ''):
    global args
    method = method + ' ' if method != '' else ''
    if args.deflate:
        file_tests(method + 'Deflate', zip_arg, unzip_arg)
    if args.raw:
        file_tests(method + 'Raw', '-0 ' + zip_arg, unzip_arg)
    if args.bzip2:
        file_tests(method + 'BZIP2', '-b ' + zip_arg, unzip_arg)
    if args.lzma:
        file_tests(method + 'LZMA', '-m ' + zip_arg, unzip_arg)

def empty_zip_test():
    unzip('empty.zip', 'out')

def sfx_zip_test():
    org_exe = get_exec('minizip')
    sfx_exe = org_exe.replace('.exe', '') + '_sfx.exe'
    shutil.copyfile(org_exe, sfx_exe)
    zip_list_unzip(sfx_exe, 'out', '-a', '', [ 'test.c', 'test.h' ])

if not os.path.exists('repo'):
    os.system('git clone https://github.com/nmoinvaz/minizip repo')

# Run tests
#empty_zip_test()
#sfx_zip_test()
compression_method_tests()
if args.pkcrypt:
    compression_method_tests('PKCrypt', '-p 1234567890', '-p 1234567890')
if args.wzaes:
    compression_method_tests('WinZipAES', '-s -p 1234567890', '-p 1234567890')
if args.split:
    compression_method_tests('Disk Span', '-k 1024', '')
if args.zipcd:
    compression_method_tests('ZipCD', '-z', '')
if args.sign:
    compression_method_tests('Signing', '-h ia.p12 -w test', '')