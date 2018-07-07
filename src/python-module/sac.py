#!/usr/bin/python

import gdb
import os
import sys

# Import module from current directory
symbolicfile = os.path.abspath(os.path.expanduser(__file__))
sys.path.insert(0, os.path.dirname(symbolicfile))

from build import build
from buildUtils import parseSac
from families import *
from gdbUtils import *
from libInjection import *
from linkMap import *
from patchSymbols import *
from pprint import pprint


class SacCommand (gdb.Command):
    "Command to update the code in real time."

    def __init__(self):
        super (SacCommand, self).__init__("sac", gdb.COMMAND_RUNNING,
                                          gdb.COMPLETE_FILENAME)
        self.patches = {} # Dictionnary of couple (address, Patch)
        self.builds = {} # Dictionnary for building commands (filename, command)
        self.families = Families() # Dictionnary of couple (symbol, Browser)
        self.default_build = ["gcc", "-c"]

        gdb.execute('handle SIGSEGV nopass')

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if not len(argv): # Called by a hook
            return patch_symbol(self.patches)


        if argv[0] == "--build-file":
            return parseSac(argv[1], self.builds)

        gdb.write("Building... ");
        path = build(argv, self.builds, self.default_build)
        if not path:
            gdb.write("Build failed\n", gdb.STDERR)
            return None
        gdb.write("Done\n");

        if not patch_objfile(path, self.patches, self.families):
            gdb.write("Failed to change {0}\n".format(path), gdb.STDERR)



    def sigsegv_handler(self):
        cli_out = gdb.execute('p /x $_siginfo._sifields._sigfault.si_addr',
                              False, True)
        segv_addr = int(cli_out.split(' ')[-1], 16)
        gdb.write("Segv at %s\n" % hex(segv_addr), gdb.STDERR)
#        if not self.families.try_patch(segv_addr):
#            gdb.execute('signal SIGSEGV')


    def test(self):
        self.families.print()


def patch_objfile(lib_path, patches, families):
    inf = gdb.selected_inferior()
    handle = get_handle(lib_path)
    inject_addr = get_injection_addr() + 0x10

    # Close old version if any
    if handle:
        gdb.write("Closing the old version...", gdb.STDERR)
        families.restore_shared_lib(lib_path)
        if not close_shared_lib(inject_addr, inf, handle):
            gdb.write("Failed\n")
            return False
        gdb.write("Done\n", gdb.STDERR)

    # Open the shared library
    lib_handle = open_shared_lib(inject_addr, inf, lib_path)
    if not lib_handle:
        gdb.write("Failed to load the shared library\n", gdb.STDERR)
        return False

    # Patch the symbols
    if not patch_symbols(lib_path, inf, lib_handle, patches, families):
        gdb.write("Failed to patch symbols from {0}\n".format(lib_path), gdb.STDERR)
        if not close_shared_lib(0, inf, handle):
            gdb.write("Failed to clean up\n", gdb.STDERR)

        return False

    gdb.write("Code successfully updated\n")
    return True



def static_var(varname, value):
    def decorate(func):
        setattr(func, varname, value)
        return func
    return decorate



if __name__ == '__main__':
    sac = SacCommand()

    @static_var('sac', sac)
    def stop_handler(event):
        if isinstance(event, gdb.SignalEvent):
            if event.stop_signal == 'SIGSEGV':
                stop_handler.sac.sigsegv_handler()

    gdb.events.stop.connect(stop_handler)
