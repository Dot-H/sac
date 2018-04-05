import gdb
import os.path
import subprocess
import copy

def extension_idx(filename):
    idx = len(filename) - 1
    for c in reversed(filename):
        if c == '.':
            return idx

        idx -= 1

    return idx


def output_lib_path(objs):
    out = "/tmp/sac"

    #Every build with the same files must have the same name
    objs = sorted(objs)
    print(objs)
    for f in objs:
        basename = os.path.basename(f)
        ext_idx = extension_idx(basename)
        if ext_idx != -1:
            basename = basename[0:ext_idx]
        out += '_' + basename

    out += '.so'
    return out


def build_objs(paths, builds, default_build):
    objs = []

    for f in paths:
        cmd = builds.get(f)
        if not cmd:
            cmd = copy.copy(default_build)

        cmd.insert(1, '-fPIC')
        cmd += [f]
        f = '/tmp/' + os.path.basename(f)
        ext_idx = extension_idx(f)
        if ext_idx != -1:
            f = f[0:ext_idx]

        f += '.o'
        cmd += ['-o', f]
        objs += [f]
        print(cmd)
        subprocess.check_call(cmd)


    return objs
    


def build(paths, builds, default_build, compiler = 'gcc'):
    objs = build_objs(paths, builds, default_build)
    print("objs:", objs)
    if not objs:
        gdb.write("Failed to build object files\n", gdb.STDERR)
        return None

    output_lib = output_lib_path(objs)
    cmd = [compiler, '-shared', '-o', output_lib] + objs 
    print(cmd)

    try:
        subprocess.check_call(cmd)
    except:
        return None

    return output_lib
