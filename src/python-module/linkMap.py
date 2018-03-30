import copy
import gdb

from ctypes import *

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


def get_link_map(inferior = gdb.selected_inferior()):
    cli_out = gdb.execute("p *(long *)((char *)&_r_debug + 8)", False, True)
    addr = int(cli_out.split(' ')[-1])
    if not addr:
        gdb.write("Inferior has no link map yet\n")
        return None

#Cast memory view to C - contiguous unsigned char buffer
    mv_lnk_map = inferior.read_memory(addr, sizeof(LinkMap)).cast('B')
    lnk_map = LinkMap.from_buffer(mv_lnk_map)

    return lnk_map
