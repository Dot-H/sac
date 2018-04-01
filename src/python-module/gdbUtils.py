import gdb

from pprint import pprint

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


def sym_addr(funcname, domain = None):
    block = gdb.selected_frame().block()
    if not domain:
        sym = gdb.lookup_symbol(funcname)[0]
    else:
        sym = gdb.lookup_symbol(funcname, block, domain)[0]

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
