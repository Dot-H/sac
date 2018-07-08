import gdb
import re

from linkMap import *
from gdbUtils import *

# TODO: Automation of the loading by reading injected-code.o
#payload_open_shared = b'\x41\x52\x56\xff\xd2\xcc\x41\x59\x50\x48\x89\xc7\x48\x48\x31\xf6\x48\xff\xc6\x41\xff\xd1\x5f\x41\x59\x50\x41\xff\xd1\x58\xcc'
payload_open_shared = b'\x41\x52\x56\xff\xd2\xcc\x41\x59\x50\x48\x89\xc7\x48\x31\xf6\x48\xc7\xc6\x02\x00\x00\x00\x41\xff\xd1\x5f\x41\x59\x50\x41\xff\xd1\x58\xcc'
payload_close_shared = b'\xff\xd6\xcc'
payload_rm_write_protect = b'\x49\x89\xd1\xb8\x01\x00\x00\x00\x89\xc2\x41\xff\xd1\xcc'
payload_add_write_protect = b'\x49\x89\xd1\xb8\x03\x00\x00\x00\x89\xc2\x41\xff\xd1\xcc'


def get_injection_addr():
    raw_stats = gdb.execute("info proc stat", False, True)
    stats = re.split(':|\n', raw_stats)
    addr_section_text = stats[stats.index('Start of text') + 1]
    return int(addr_section_text, 16)


def close_shared_lib(inject_addr, inferior, handle):
    handle = hex(handle)
    cmd = f'call (int)__libc_dlclose((void *){handle})'
    gdb.write(f"\nCalling {cmd}\n", gdb.STDERR)
    ret = int(gdb.execute(cmd, False, True).split(' ')[-1], 16)
    if ret != 0:
        return True

    return False


def get_handle(lib_path):
    lnk_map = get_linkmap()

    prv = 0 # The first one is a sentinel, it cannot be returned
    handle = None
    for lib in lnk_map:
        if lib.get_name() == lib_path:
            handle = prv
            break

        prv = lib.l_next

    return handle


def open_shared_lib(inject_addr, inferior, lib_path):
    cmd = f'call (void *)__libc_dlopen_mode("{lib_path}", 0x00002)'
    gdb.write(f"\nCalling {cmd}\n", gdb.STDERR)
    handle = int(gdb.execute(cmd, False, True).split(' ')[-1], 16)
    if not handle: # Checking return value
        gdb.write("failed to load library\n", gdb.STDERR)
        return None

    return handle



def chg_pg_prot(inject_addr, inferior, pg_addr, has_write_prot=True):
    prot = '0x00003' if has_write_prot else '0x00001'

    pg_addr = hex(pg_addr)
    cmd = f'call (int)mprotect((void *){pg_addr}, 4096, {prot})'
    gdb.write(f"\nCalling {cmd}\n", gdb.STDERR)
    cli_out = gdb.execute(cmd, False, True)
    ret = int(cli_out.split(' ')[-1], 16)
    if ret == -1:
        return False

    return True
