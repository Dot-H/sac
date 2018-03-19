#!/usr/bin/python

import gdb
import socket
import threading
from pprint import pprint
import sys

sac = None
"""open_shared_code = "\x48\x29\xf4\xcc\x49\x89\xf9\x48\x89\xe7\x48\x31\xf6\x48\xff\xc6\x41\xff\xd1\xcc"

def open_shared(dlopen_addr, inject_addr, inferior, frame):
    sv_buf = inferior.read_memory(inject_addr, len(open_shared_code))
    sv_regs = gdb.parse_and_eval('info registers')
    
    new_regs = gdb.registers(sv_regs)
    new_regs.rip = inject_addr
    new_regs.rdi = dlopen_addr
    new_regs.rsi = len(open_shared_code)
    gdb.write_regs(new_regs)

    gdb.cont()

    new_regs = gdb.read_regs()
    inferior.write_memory(new_regs.rsp, open_shared_code)

    gdb.cont()

    new_regs = gdb.read_regs()
    if new_regs.rax == 0:
        return None

    gdb.write_regs(sv_regs)
    gdb.write_memory(sv_buf)
    """

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

def read_func(funcname):
        try:
            gdb.execute('info registers', True, True)
            #pprint(sv_regs)
        except gdb.error:
            gdb.write("Failed to parse and eval\n", gdb.STDERR)
        sym = gdb.lookup_symbol(funcname)[0]
        if (not sym or not sym.is_valid() or not sym.is_function):
            gdb.write("Symbol is not a valid function\n", gdb.STDERR)
            return

        addr = sym.value()
        pprint(int(addr.address))

        gdb.write(str(sym.print_name))

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
            self.rax    = frame.read_register('rax')
            self.rax    = frame.read_register('rax')
            self.rbx    = frame.read_register('rbx')
            self.rcx    = frame.read_register('rcx')
            self.rdx    = frame.read_register('rdx')
            self.rsi    = frame.read_register('rsi')
            self.rdi    = frame.read_register('rdi')
            self.rbp    = frame.read_register('rbp')
            self.rsp    = frame.read_register('rsp')
            self.r8     = frame.read_register('r8')
            self.r9     = frame.read_register('r9')
            self.r10    = frame.read_register('r10')
            self.r11    = frame.read_register('r11')
            self.r12    = frame.read_register('r12')
            self.r13    = frame.read_register('r13')
            self.r14    = frame.read_register('r14')
            self.r15    = frame.read_register('r15')
            self.rip    = frame.read_register('rip')
            self.eflags = frame.read_register('eflags')

class Listener (threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.s = None
        self.stoprequest = threading.Event()

    def join(self, timeout=None):
        self.stoprequest.set()
        if self.s != None:
            self.s.close()
        super(Listener, self).join(timeout)

    def run(self):
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setblocking(False)
            self.s.bind((socket.gethostname(), 1111))
            self.s.listen(5)
            while not self.stoprequest.isSet():
                try:
                    (clientsocket, address) = self.s.accept()
                    dump_objfile(gdb.objfiles())
                    read_func("foo")
                    clientsocket.close()
                except socket.error:
                    continue


class SacCommand (gdb.Command):
    "Command to update the code in real time."
    
    def __init__(self):
        super (SacCommand, self).__init__("sac", gdb.COMMAND_RUNNING,
                                          gdb.COMPLETE_NONE)
        self.listener = Listener(1, "FileListener", 1)

    def invoke(self, arg, from_tty):
        self.listener.start() 
        try:
            x86GenRegisters(gdb.selected_frame())

sac = SacCommand()
