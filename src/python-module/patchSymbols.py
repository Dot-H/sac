import gdb
import struct

from readSymbols import read_symbols
from linkMap import get_linkmap_at
from gdbUtils import *

NBYTES_X86_REL_JMP32 = 5

class Patch(object):
    def __init__(self, symbol, new_addr, breakpoint):
        self.symbol = symbol
        self.new_addr = new_addr
        self.breakpoint = breakpoint



def put_hook(symbol, new_addr, patches):
    lookup_addr = sym_addr(symbol)
    if not lookup_addr or lookup_addr == new_addr:
        return

    bp_spec = "*{0}".format(lookup_addr)
    bp = gdb.Breakpoint(bp_spec, gdb.BP_BREAKPOINT, True, True)
    patches[lookup_addr] = Patch(symbol, new_addr, bp)



def patch_function(symbol, new_addr):
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
    value = inf.read_memory(lookup_addr, sz) 
    inf.write_memory(new_addr, value)

    gdb.write("Done\n", gdb.STDERR)



def patch_symbol(patches):
    regs = x86GenRegisters(gdb.selected_frame())
    patch = patches.get(regs.rip)
    if not patch:
        return

    patch_function(patch.symbol, patch.new_addr)
    val = patches.pop(regs.rip)
    val.breakpoint.delete()
    gdb.execute("continue") # Was stoped by a hook



def patch_symbols(path, inf, lib_handle, patches):
    symbols = read_symbols(path)
    print(hex(lib_handle))
    lib_addr = get_linkmap_at(lib_handle).l_addr

    for symbol, entry in symbols.items():
        new_addr = entry['st_value'] + lib_addr
        if entry['st_info']['type'] == 'STT_FUNC':
            put_hook(symbol, new_addr, patches)
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
