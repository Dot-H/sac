import gdb
import re

from linkMap import *
from gdbUtils import *

payload_open_shared = b'\x41\x52\x56\xff\xd2\xcc\x41\x59\x50\x48\x89\xc7\x48\xbe\x01\x00\x00\x00\x00\x00\x00\x00\x41\xff\xd1\x5f\x41\x59\x50\x41\xff\xd1\x58\xcc'
payload_close_shared = b'\xff\xd6\xcc'

def get_injection_addr():
    raw_stats = gdb.execute("info proc stat", False, True)
    stats = re.split(':|\n', raw_stats)
    addr_section_text = stats[stats.index('Start of text') + 1]
    print("Found address %s", addr_section_text)
    return int(addr_section_text, 16)

def close_shared_lib(inject_addr, inferior, handle):
    sv_regs = x86GenRegisters(gdb.selected_frame())
    print("handle: 0x%lx" % handle)

    sv_code = inferior.read_memory(inject_addr, len(payload_close_shared))
    inferior.write_memory(inject_addr, payload_close_shared)

    new_regs = copy.copy(sv_regs)
    new_regs.rip = inject_addr
    new_regs.rdi = handle
    new_regs.rsi = sym_addr("__libc_dlclose")
    write_regs(new_regs, ["rip", "rdi", "rsi"])

    gdb.execute("continue")

    new_regs = x86GenRegisters(gdb.selected_frame())
    ret = new_regs.rax == 0
    if not ret:
        gdb.write("Failed to close the already present lib\n", gdb.STDERR)
        pprint(new_regs.rax)


    restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
    return ret


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
    handle = get_handle(lib_path)
    if handle:
        gdb.write("Closing the old version...\n")
        if not close_shared_lib(inject_addr, inferior, handle):
            return None

    handle = None
    lib_length = len(lib_path) + 1 # +1 for null byte

    gdb.write("Writing payload in inferor's memory...\n")
    sv_regs = x86GenRegisters(gdb.selected_frame())

    sv_code = inferior.read_memory(inject_addr, len(payload_open_shared))
    inferior.write_memory(inject_addr, payload_open_shared)

    gdb.write("Setting inferior's registers...\n")
    new_regs = copy.copy(sv_regs)
    new_regs.rip = inject_addr
    new_regs.rdi = lib_length
    new_regs.rsi = sym_addr("__libc_dlopen_mode")
    if not new_regs.rsi:
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return None

    new_regs.rdx = sym_addr("malloc")
    if not new_regs.rdx:
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return None

    new_regs.r10 = sym_addr("free")
    if not new_regs.r10:
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return None

    write_regs(new_regs, ["rip", "rdi", "rsi", "rdx", "r10"])
    gdb.execute("continue")
    

    gdb.write("Writing lib path...\n")
    new_regs = x86GenRegisters(gdb.selected_frame())

    if not new_regs.rax:
        gdb.write("Failed to malloc libname\n", gdb.STDERR)
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
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
    print("handle: 0x%lx" % handle)
    return handle
