import gdb
import struct

from readSymbols import read_symbols
from linkMap import get_linkmap_at
from gdbUtils import sym_addr

NBYTES_X86_REL_JMP32 = 5

def patch_symbols(path, inf, lib_handle):
    symbols = read_symbols(path)
    lib_addr = get_linkmap_at(lib_handle).l_addr

    for symbol, entry in symbols.items():
        lookup_addr = sym_addr(symbol)
        new_addr = entry['st_value'] + lib_addr
        if lookup_addr and lookup_addr != new_addr:
            gdb.write("Patching {0}... ".format(symbol), gdb.STDERR)
            inject_jumpto(lookup_addr, new_addr) 
            lookup_addr = sym_addr("{0}@plt".format(symbol))
            if lookup_addr:
                inject_jumpto(lookup_addr, new_addr)

            gdb.write("Done\n", gdb.STDERR)

    return True

def x86_build_abs_jmp64(jmp_addr):
    return struct.pack("BB", 0x48, 0xb8) + \
           struct.pack("<Q", jmp_addr) + \
           struct.pack("BB", 0xff, 0xe0)


def inject_jumpto(addr, new_addr, inf = gdb.selected_inferior()):
    code = x86_build_abs_jmp64(new_addr)
    inf.write_memory(addr, code)
    return True
