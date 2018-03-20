#!/usr/bin/python

import gdb
import socket
import threading
from pprint import pprint
import copy
import sys
 
sac = None
open_shared_code = b'\x48\x29\xf4\xcc\x49\x89\xf9\x48\x89\xe7\x48\x31\xf6\x48\xff\xc6\x41\xff\xd1\xcc'

def open_shared(dlopen_addr, inject_addr, inferior, frame, lib_path):
    res = True

    sv_regs = x86GenRegisters(frame)
    inject_addr = sv_regs.rip #FIXME
    sv_buf = inferior.read_memory(inject_addr, len(open_shared_code))
    inferior.write_memory(inject_addr, open_shared_code)
    pprint(sv_buf.hex())

    new_regs = copy.copy(sv_regs)
    new_regs.rip = inject_addr
    new_regs.rdi = dlopen_addr
    new_regs.rsi = len(lib_path) + 1
    write_regs(new_regs, ["rip", "rdi", "rsi"])

    gdb.execute("continue")

    new_regs = x86GenRegisters(frame)
    inferior.write_memory(new_regs.rsp, lib_path + '\0')

    gdb.execute("continue")

    new_regs = x86GenRegisters(frame)
    if new_regs.rax == 0:
        gdb.write("failed to load library\n", gdb.STDERR)
        res = False

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
    inferior.write_memory(inject_addr, sv_buf)
    gdb.execute("continue")
    return res

def write_regs(regs, to_write):
    for reg in to_write:
        cmd = "set ${0} = {1}".format(reg, hex(getattr(regs, reg)))
        pprint(cmd)
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
            res = gdb.execute("p " + funcname, False, True)
            addr_tab = res.split(' ')
            # TODO Check for function name matching
            addr = int(addr_tab[-2], 16)
            pprint(hex(addr))
            return addr
        except gdb.error:
            gdb.write("Symbol is not a valid function\n", gdb.STDERR)
            return None

    addr = sym.value()
    pprint(hex(int(addr.address)))
    return int(addr.address)

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
        dlopen_addr = func_addr("__libc_dlopen_mode")
        open_shared(dlopen_addr, 0, gdb.selected_inferior(),
                gdb.selected_frame(), "/home/doth/EPITA/lse/sac/build/test.so")

SacCommand()
