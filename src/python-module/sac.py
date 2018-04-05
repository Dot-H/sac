#!/usr/bin/python

import gdb
import sys
import os
from pprint import pprint

# Import module from current directory
symbolicfile = os.path.abspath(os.path.expanduser(__file__))
sys.path.insert(0, os.path.dirname(symbolicfile))

from linkMap import *
from gdbUtils import *
from libInjection import *
from patchSymbols import *
from build import build


class SacCommand (gdb.Command):
    "Command to update the code in real time."

    def __init__(self):
        super (SacCommand, self).__init__("sac", gdb.COMMAND_RUNNING,
                                          gdb.COMPLETE_FILENAME)
        self.patches = {} #Dictionnary of couple (address, Patch)
        self.builds = {} #Dictionnary for building commands (filename, command)
        self.default_build = ["gcc", "-c"]

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if not len(argv): # Called by a hook
            return patch_symbol(self.patches)

#        path = "/home/doth/EPITA/lse/sac/build/test.so"
        path = build(argv, self.builds, self.default_build)
        if not path:
            gdb.write("Build failed\n", gdb.STDERR)
            return None

        if not patch_objfile(path, self.patches):
            gdb.write("Failed to change {0}\n".format(path), gdb.STDERR)



def static_var(varname, value):
    def decorate(func):
        setattr(func, varname, value)
        return func
    return decorate



@static_var('sac', False)
def new_objfile_event(event):
    print("New objfile: {0}".format(event.new_objfile.filename))
    if not new_objfile_event.sac:
        print("Connecting to sources")
        new_objfile_event.sac = True



def patch_objfile(path, patches):
    inf = gdb.selected_inferior()
    lib_handle = open_shared_lib(get_injection_addr() + 0x10, inf, path)
    if not lib_handle:
        gdb.write("Failed to load the shared library\n", gdb.STDERR)
        return False

    if not patch_symbols(path, inf, lib_handle, patches):
        gdb.write("Failed to patch symbols from {0}\n".format(path), gdb.STDERR)
        if not close_shared_lib(0, inf, handle):
            gdb.write("Failed to clean up\n", gdb.STDERR)

        return False

    gdb.write("Code successfully updated\n")
    return True



if __name__ == '__main__':
#gdb.events.new_objfile.connect(new_objfile_event)
    SacCommand()
