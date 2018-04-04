import gdb
import struct

from readSymbols import read_symbols
from linkMap import get_linkmap_at
from gdbUtils import sym_addr

NBYTES_X86_REL_JMP32 = 5

def patch_function(symbol, entry, new_addr):
    lookup_addr = sym_addr(symbol)
    if not lookup_addr or lookup_addr == new_addr:
        return

    gdb.write("Patching {0}... ".format(symbol), gdb.STDERR)

    inject_jumpto(lookup_addr, new_addr) 

    gdb.write("Done\n", gdb.STDERR)


def patch_object(symbol, entry, new_addr):
    lookup_addr = sym_addr("&"+symbol)
    if not lookup_addr or lookup_addr == new_addr:
        return

    gdb.write("Patching {0}... ".format(symbol), gdb.STDERR)

    sz = entry['st_size'];
    inf = gdb.selected_inferior()
    value = inf.read_memory(new_addr, sz) 
    inf.write_memory(lookup_addr, value)

    gdb.write("Done\n", gdb.STDERR)


def patch_symbols(path, inf, lib_handle):
    symbols = read_symbols(path)
    lib_addr = get_linkmap_at(lib_handle).l_addr

    for symbol, entry in symbols.items():
        new_addr = entry['st_value'] + lib_addr
        if entry['st_info']['type'] == 'STT_FUNC':
            patch_function(symbol, entry, new_addr)
        else:
            patch_object(symbol, entry, new_addr)
    
    return True


def x86_build_abs_jmp64(jmp_addr):
    return struct.pack("BB", 0x48, 0xb8) + \
           struct.pack("<Q", jmp_addr) + \
           struct.pack("BB", 0xff, 0xe0)


def inject_jumpto(addr, new_addr, inf = gdb.selected_inferior()):
    code = x86_build_abs_jmp64(new_addr)
    inf.write_memory(addr, code)
    return True
