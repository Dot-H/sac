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
    sv_regs = x86GenRegisters(gdb.selected_frame())

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
    lib_length = len(lib_path) + 1 # +1 for null byte

    gdb.write("Writing payload in inferior's memory...\n", gdb.STDERR)
    sv_regs = x86GenRegisters(gdb.selected_frame())

    sv_code = inferior.read_memory(inject_addr, len(payload_open_shared))
    inferior.write_memory(inject_addr, payload_open_shared)

    gdb.write("Setting inferior's registers...\n", gdb.STDERR)
    new_regs = copy.copy(sv_regs)
    new_regs.rip = inject_addr
    new_regs.rdi = lib_length
    new_regs.rsi = sym_addr("__libc_dlopen_mode")
    new_regs.rdx = sym_addr("malloc")
    new_regs.r10 = sym_addr("free")
    if not new_regs.rsi or not new_regs.rdx or not new_regs.r10:
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return None

    gdb.write("inject_addr: %s\n" % hex(inject_addr))
    write_regs(new_regs, ["rip", "rdi", "rsi", "rdx", "r10"])
    gdb.execute("continue")


    gdb.write("Writing lib path...\n", gdb.STDERR)
    new_regs = x86GenRegisters(gdb.selected_frame())

    if not new_regs.rax: # Checking return value
        gdb.write("Failed to malloc libname\n", gdb.STDERR)
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return None

    inferior.write_memory(new_regs.rax, lib_path, lib_length)
    gdb.execute("continue")

    new_regs = x86GenRegisters(gdb.selected_frame())
    handle = new_regs.rax # Checking return value
    if not handle:
        gdb.write("failed to load library\n", gdb.STDERR)
        return None

    restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
    return handle



def chg_pg_prot(inject_addr, inferior, pg_addr, has_write_prot=True):
    payload = payload_add_write_protect if has_write_prot else payload_rm_write_protect
    gdb.write("Writing payload in inferior's memory...\n", gdb.STDERR)
    sv_regs = x86GenRegisters(gdb.selected_frame())

    sv_code = inferior.read_memory(inject_addr, len(payload))
    inferior.write_memory(inject_addr, payload)

    gdb.write("Setting inferior's registers...\n", gdb.STDERR)
    new_regs = copy.copy(sv_regs)
    new_regs.rip = inject_addr
    new_regs.rdi = pg_addr
    new_regs.rsi = 4096
    new_regs.rdx = sym_addr("mprotect")
    if not new_regs.rdx:
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return False

    write_regs(new_regs, ["rip", "rdi", "rsi", "rdx"])

    gdb.write("Changing write protection...\n", gdb.STDERR)
    gdb.execute("continue")

    new_regs = x86GenRegisters(gdb.selected_frame())
    if new_regs.rax == -1: # Checking return value
        gdb.write("Failed to change write protection\n", gdb.STDERR)
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return False

    restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
    return True
