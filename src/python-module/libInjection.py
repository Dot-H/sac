import gdb
import re

from linkMap import *
from gdbUtils import *


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
    return ret == 0


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

    return handle



def chg_pg_prot(inject_addr, inferior, pg_addr, has_write_prot=True):
    prot = '0x00003' if has_write_prot else '0x00001'

    pg_addr = hex(pg_addr)
    cmd = f'call (int)mprotect((void *){pg_addr}, 4096, {prot})'
    gdb.write(f"\nCalling {cmd}\n", gdb.STDERR)
    cli_out = gdb.execute(cmd, False, True)
    ret = int(cli_out.split(' ')[-1], 16)
    return ret != -1
