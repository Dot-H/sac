#!/usr/bin/python

from ctypes import *
from pprint import pprint
import copy
import gdb
import socket
import threading
import os

# Import module from current directory
symbolicfile = os.path.abspath(os.path.expanduser(__file__))
sys.path.insert(0, os.path.dirname(symbolicfile))

from linkMap import *
from gdbUtils import *
from libInjection import *

sac = None


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

        inf = gdb.selected_inferior()
#        path = "/home/doth/EPITA/lse/sac/build/test.so"
        path = argv[0]
        if not open_shared_lib(0, inf, path):
            gdb.write("Failed to load the shared library\n", gdb.STDERR)

SacCommand()
