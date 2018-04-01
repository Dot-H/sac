#!/usr/bin/python

import sys
import os
from pprint import pprint

# Import module from current directory
symbolicfile = os.path.abspath(os.path.expanduser(__file__))
sys.path.insert(0, os.path.dirname(symbolicfile))

from linkMap import *
from gdbUtils import *
from libInjection import *
from patchSymbols import patch_symbols

class SacCommand (gdb.Command):
    "Command to update the code in real time."

    def __init__(self):
        super (SacCommand, self).__init__("sac", gdb.COMMAND_RUNNING,
                                          gdb.COMPLETE_FILENAME)

    def invoke(self, arg, from_tty):
        pprint(sizeof(LinkMap))
        argv = gdb.string_to_argv(arg)
        if (len(argv) != 1):
            gdb.write("Usage: sac /PATH/TO/LIB\n", gdb.STDERR)
            return

#        path = "/home/doth/EPITA/lse/sac/build/test.so"
        path = argv[0]
        if not patch_objfile(path):
            gdb.write("Failed to change {0}\n".format(path), gdb.STDERR)



def patch_objfile(path):
    inf = gdb.selected_inferior()
    lib_handle = open_shared_lib(0, inf, path)
    if not lib_handle:
        gdb.write("Failed to load the shared library\n", gdb.STDERR)
        return False

    if not patch_symbols(path, inf, lib_handle):
        gdb.write("Failed to patch symbols from {0}\n".format(path), gdb.STDERR)
        if not close_shared_lib(0, inf, handle):
            gdb.write("Failed to clean up\n", gdb.STDERR)

        return False

    gdb.write("Successfully updated the code\n")
    return True

if __name__ == '__main__':
    SacCommand()
