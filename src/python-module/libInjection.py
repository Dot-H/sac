import gdb

from linkMap import *
from gdbUtils import *

payload_open_shared = b'\x56\xff\xd2\xcc\x41\x59\x48\x89\xc7\x48\xbe\x01\x00\x00\x00\x00\x00\x00\x00\x41\xff\xd1\xcc'
payload_close_shared = b'\xff\xd6\xcc'

def close_shared_lib(inject_addr, inferior, handle):
    sv_regs = x86GenRegisters(gdb.selected_frame())
    inject_addr = sv_regs.rip #FIXME

    sv_code = inferior.read_memory(inject_addr, len(payload_close_shared))
    inferior.write_memory(inject_addr, payload_close_shared)

    new_regs = copy.copy(sv_regs)
    new_regs.rip = inject_addr
    new_regs.rdi = handle
    new_regs.rsi = sym_addr("__libc_dlclose", gdb.SYMBOL_FUNCTION_DOMAIN)
    write_regs(new_regs, ["rip", "rdi", "rsi"])

    gdb.execute("continue")

    new_regs = x86GenRegisters(gdb.selected_frame())
    pprint(new_regs.rax)

    restore_memory_space(sv_regs, sv_code, inject_addr, inferior)


def open_shared_lib(inject_addr, inferior, lib_path):
    lnk_map = get_linkmap()

    prv = lnk_map # The first one is a sentinel, it cannot be returned
    handle = None
    for lib in lnk_map:
        if lib.get_name() == lib_path:
            handle = lib
        prv = lib

    if handle:
        gdb.write("Closing the old version...\n")
        close_shared_lib(0, inferior, prv.l_next)

    handle = None
    lib_length = len(lib_path) + 1 # +1 for null byte

    gdb.write("Writing payload in inferor's memory...\n")
    sv_regs = x86GenRegisters(gdb.selected_frame())

    inject_addr = sv_regs.rip #FIXME

    sv_code = inferior.read_memory(inject_addr, len(payload_open_shared))
    inferior.write_memory(inject_addr, payload_open_shared)

    gdb.write("Setting inferior's registers...\n")
    new_regs = copy.copy(sv_regs)
    new_regs.rip = inject_addr
    new_regs.rdi = lib_length
    new_regs.rsi = sym_addr("__libc_dlopen_mode", gdb.SYMBOL_FUNCTION_DOMAIN)
    if not new_regs.rsi:
        handletore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return None

    new_regs.rdx = sym_addr("malloc", gdb.SYMBOL_FUNCTION_DOMAIN)
    if not new_regs.rdx:
        handletore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return None

    write_regs(new_regs, ["rip", "rdi", "rsi", "rdx"])

    gdb.execute("continue")

    gdb.write("Writing lib path...\n")
    new_regs = x86GenRegisters(gdb.selected_frame())
    if not new_regs.rax:
        gdb.write("Failed to malloc libname\n", gdb.STDERR)
        handletore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return None

    inferior.write_memory(new_regs.rax, lib_path, lib_length)

    gdb.execute("continue")

    new_regs = x86GenRegisters(gdb.selected_frame())
    handle = new_regs.rax
    if not handle:
        gdb.write("failed to load library\n", gdb.STDERR)
        return None

    pprint("return value: {0}".format(hex(new_regs.rax)))
    restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
    return handle
