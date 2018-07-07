import gdb
import struct

from readSymbols import read_symbols
from linkMap import get_linkmap_at
from libInjection import get_injection_addr, chg_pg_prot
from families import SymboleObject
from gdbUtils import *

NBYTES_X86_REL_JMP32 = 5


class Patch(object):
    def __init__(self, symbol, new_addr, breakpoint):
        self.symbol = symbol
        self.new_addr = new_addr
        self.breakpoint = breakpoint


def put_fcn_hook(symbol, new_addr, patches):
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

    gdb.write("Patching %s... " % symbol, gdb.STDERR)

    inject_jumpto(lookup_addr, new_addr)

    gdb.write("Done\n", gdb.STDERR)



# Assume the user did not change the size of the object. Only a fool
# would break the only rule!
def patch_object(lib_path, symbol, entry, new_addr, families):
    lookup_addr = sym_addr("&"+symbol)
    if not lookup_addr or lookup_addr == new_addr:
        return

    gdb.write("Patching %s... " % symbol, gdb.STDERR)

    sz = entry['st_size'];
    sym_obj = SymboleObject(new_addr, sz)
    lookup_obj = SymboleObject(lookup_addr, sz)

    #TODO: Try to insert it only the first time
    if not families.insert(lib_path, symbol, lookup_obj) or \
       not families.insert(lib_path, symbol, sym_obj):
        gdb.write("Failed\n", gdb.STDERR)
    else:
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


def patch_symbols(path, inf, lib_handle, patches, families):
    symbols = read_symbols(path)
    link_map = get_linkmap_at(lib_handle)
    lib_addr = link_map.l_addr
    lib_path = link_map.get_name()

    print("lib_path: %s" % lib_path)
    for symbol, entry in symbols.items():
        new_addr = entry['st_value'] + lib_addr
        if entry['st_info']['type'] == 'STT_FUNC':
            put_fcn_hook(symbol, new_addr, patches)
        else:
            patch_object(lib_path, symbol, entry, new_addr, families)

    return True



def x86_build_abs_jmp64(jmp_addr):
    return struct.pack("BB", 0x48, 0xb8) + \
           struct.pack("<Q", jmp_addr) + \
           struct.pack("BB", 0xff, 0xe0)



def inject_jumpto(addr, new_addr, inf = gdb.selected_inferior()):
    code = x86_build_abs_jmp64(new_addr)
    inf.write_memory(addr, code)
    return True
