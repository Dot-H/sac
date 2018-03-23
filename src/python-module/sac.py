#!/usr/bin/python

from ctypes import *
from pprint import pprint
import copy
import gdb
import socket
import threading

sac = None
payload_open_shared = b'\x56\xff\xd2\xcc\x41\x59\x48\x89\xc7\x48\xbe\x01\x00\x00\x00\x00\x00\x00\x00\x41\xff\xd1\xcc'
payload_close_shared = b'\xff\xd6\xcc'

def restore_memory_space(sv_regs, sv_code, inject_addr, inferior):
    gdb.write("Restoring inferior's state...\n")
    #FIXME generic way
    write_regs(sv_regs, ["rax",
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "rip",
            "eflags"])
    inferior.write_memory(inject_addr, sv_code)

def close_shared_lib(inject_addr, inferior, handle):
    sv_regs = x86GenRegisters(gdb.selected_frame())
    inject_addr = sv_regs.rip #FIXME

    sv_code = inferior.read_memory(inject_addr, len(payload_close_shared))
    inferior.write_memory(inject_addr, payload_close_shared)

    new_regs = copy.copy(sv_regs)
    new_regs.rip = inject_addr
    new_regs.rdi = handle
    new_regs.rsi = func_addr("__libc_dlclose")
    write_regs(new_regs, ["rip", "rdi", "rsi"])

    gdb.execute("continue")

    new_regs = x86GenRegisters(gdb.selected_frame())
    pprint(new_regs.rax)

    restore_memory_space(sv_regs, sv_code, inject_addr, inferior)

def get_link_map(inferior = gdb.selected_inferior()):
    cli_out = gdb.execute("p *(long *)((char *)&_r_debug + 8)", False, True)
    addr = int(cli_out.split(' ')[-1])
    if not addr:
        gdb.write("Inferior has no link map yet\n")
        return None
    
    # Cast memory view to C-contiguous unsigned char buffer
    mv_lnk_map = inferior.read_memory(addr, sizeof(LinkMap)).cast('B')
    lnk_map = LinkMap.from_buffer(mv_lnk_map)

    return lnk_map

def open_shared_lib(inject_addr, inferior, lib_path):
    lnk_map = get_link_map()

    prv = lnk_map # The first one is a sentinel, it cannot be returned
    res = None
    for lib in lnk_map:
        if lib.get_name() == lib_path:
            res = lib
        prv = lib

    if res:
        gdb.write("Closing the old version...\n")
        close_shared_lib(0, inferior, prv.l_next)

    res = True
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
    new_regs.rsi = func_addr("__libc_dlopen_mode")
    if not new_regs.rsi:
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return False

    new_regs.rdx = func_addr("malloc")
    if not new_regs.rdx:
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return False

    write_regs(new_regs, ["rip", "rdi", "rsi", "rdx"])

    gdb.execute("continue")

    gdb.write("Writing lib path...\n")
    new_regs = x86GenRegisters(gdb.selected_frame())
    if not new_regs.rax:
        gdb.write("Failed to malloc libname\n", gdb.STDERR)
        restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
        return False

    inferior.write_memory(new_regs.rax, lib_path, lib_length)

    gdb.execute("continue")

    new_regs = x86GenRegisters(gdb.selected_frame())
    if not new_regs.rax:
        gdb.write("failed to load library\n", gdb.STDERR)
        res = False

    pprint("return value: {0}".format(hex(new_regs.rax)))
    restore_memory_space(sv_regs, sv_code, inject_addr, inferior)
    return res


def write_regs(regs, to_write, debug = False):
    for reg in to_write:
        cmd = "set ${0} = {1}".format(reg, hex(getattr(regs, reg)))
        if debug:
            gdb.write(cmd)

        gdb.execute(cmd)


def dump_objfile(objfiles):
    for f in objfiles:
        try:
            if f.filename:
                gdb.write(f.filename + '\n')
                gdb.write(f.build_id + '\n')
                frame = gdb.selected_frame()
                if not frame.is_valid():
                    continue
                sym_n_line = frame.find_sal()
                sym = sym_n_line.symtab
                if not sym or not sym.is_valid():
                    continue

                gdb.write("filename: " + sym.filename + '\n')
            else:
                gdb.write("no filename\n", gdb.stderr)
        except gdb.error:
            continue


def func_addr(funcname):
    sym = gdb.lookup_global_symbol(funcname, gdb.SYMBOL_FUNCTIONS_DOMAIN)
    if (not sym or not sym.is_valid() or not sym.is_function):
        try:
            pprint(funcname)
            res = gdb.execute("p " + funcname, False, True)
            addr_tab = res.split(' ')
            # TODO Check for function name matching
            addr = int(addr_tab[-2], 16)
            return addr
        except gdb.error:
            gdb.write("Symbol is not a valid function\n", gdb.STDERR)
            return None

    addr = sym.value()
    return int(addr.address)


class LinkMap(Structure): # Get the current inferior at each iteration be careful
    _fields_= [("l_addr", c_uint64),
               ("l_name", c_void_p),
               ("l_ld", c_void_p),
               ("l_next", c_void_p),
               ("l_prev", c_void_p)]

    def __iter__(self):
        self.backup = LinkMap(self.l_addr, self.l_name,
                              self.l_ld, self.l_next, self.l_prev)
        return self

    def __next__(self):
        if not self.l_next:
            self.copy(self.backup)
            raise StopIteration

        inferior = gdb.selected_inferior()
        next_lm = inferior.read_memory(self.l_next, sizeof(LinkMap)).cast('B')
        tmp = LinkMap.from_buffer(next_lm) 
        self.copy(tmp)

        return self

    def copy(self, cp):
        self.l_addr = cp.l_addr
        self.l_name = cp.l_name
        self.l_ld   = cp.l_ld
        self.l_next = cp.l_next
        self.l_prev = cp.l_prev

    def get_name(self):
        if not self.l_name:
            return None

        cmd = "x/s (char *){0}".format(hex(self.l_name))
        cli_out = gdb.execute(cmd, False, True)

        op_dquote = cli_out.find('"')
        if op_dquote == -1:
            return -1

        cl_dquote = cli_out.find('"', op_dquote + 1)
        if cl_dquote == -1:
            return -1

        return cli_out[op_dquote + 1:cl_dquote]



class x86GenRegisters:
    def __init__(self, frame=None):
        if not frame:
            self.rax    = 0
            self.rax    = 0
            self.rbx    = 0
            self.rcx    = 0
            self.rdx    = 0
            self.rsi    = 0
            self.rdi    = 0
            self.rbp    = 0
            self.rsp    = 0
            self.r8     = 0
            self.r9     = 0
            self.r10    = 0
            self.r11    = 0
            self.r12    = 0
            self.r13    = 0
            self.r14    = 0
            self.r15    = 0
            self.rip    = 0
            self.eflags = 0
        else:
            self.rax    = int(frame.read_register('rax'))
            self.rax    = int(frame.read_register('rax'))
            self.rbx    = int(frame.read_register('rbx'))
            self.rcx    = int(frame.read_register('rcx'))
            self.rdx    = int(frame.read_register('rdx'))
            self.rsi    = int(frame.read_register('rsi'))
            self.rdi    = int(frame.read_register('rdi'))
            self.rbp    = int(frame.read_register('rbp'))
            self.rsp    = int(frame.read_register('rsp'))
            self.r8     = int(frame.read_register('r8'))
            self.r9     = int(frame.read_register('r9'))
            self.r10    = int(frame.read_register('r10'))
            self.r11    = int(frame.read_register('r11'))
            self.r12    = int(frame.read_register('r12'))
            self.r13    = int(frame.read_register('r13'))
            self.r14    = int(frame.read_register('r14'))
            self.r15    = int(frame.read_register('r15'))
            self.rip    = int(frame.read_register('rip'))
            self.eflags = int(frame.read_register('eflags'))


class SacCommand (gdb.Command):
    "Command to update the code in real time."

    def __init__(self):
        super (SacCommand, self).__init__("sac", gdb.COMMAND_RUNNING,
                                          gdb.COMPLETE_FILENAME)

    def invoke(self, arg, from_tty):
        pprint(sizeof(LinkMap))

        if not open_shared_lib(0, gdb.selected_inferior(),
               "/home/doth/EPITA/lse/sac/build/test.so"):
            gdb.write("Failed to load the shared library\n", gdb.STDERR)

SacCommand()
