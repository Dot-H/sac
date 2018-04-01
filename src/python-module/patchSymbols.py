from readSymbols import read_symbols
from linkMap import get_linkmap_at

NBYTES_X86_REL_JMP32 = 5

def patch_symbols(path, inf, lib_handle):
    symbols = read_symbols(path)
    lib_addr = get_linkmap_at(lib_handle).l_addr

    for symbol, entry in symbols.items():
        sym_addr = gdb.lookup_symbol(funcname)[0]
        if (sym_addr):
            gdb.write("Patching {0}... ".format(symbol), gdb.STDERR)
            inject_jumpto(sym_addr, entry['st_addr'] + lib_addr) 
            gdb.write("Done\n", gdb.STDERR)

    return True

def x86_build_abs_jmp64(jmp_addr):
    return struct.pack("<BBQBB", 0x48, 0xb8, jmp_addr, 0xff, 0xe0)

def x86_build_rel_jmp32(rip, target_addr):
    jmp_len = target_addr - (rip + NBYTES_X86_REL_JMP32) 

def inject_jumpto(cur_addr, new_addr, inf = gdb.selected_inferior()):

    return True
