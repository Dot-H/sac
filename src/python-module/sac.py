#!/usr/bin/python

import gdb
import inotify.constants
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
from notifier import Notifier
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
        self.modifications = set() # Contains source files to build
        self.default_build = ["gcc", "-c"]
        self.notifier = Notifier(self.modifications)
        self.notifier.start()

        gdb.execute('handle SIGSEGV nopass')
        gdb.execute('handle %s stop nopass' % self.notifier.sigrt_str)
        gdb.write("Please use --build-file and/or --add-files in order"
                  " to connect\nto the source files.\n", gdb.STDERR)


    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if not len(argv): # Called by a hook
            return patch_symbol(self.patches)

        if argv[0] == "--build-file":
            parseSac(argv[1], self.builds)
            files = [f for f in self.builds]
            self.add_files(files)
            return True

        if argv[0] == "--add-files":
            if len(argv[1:]) == 0:
                gdb.write("No file given\n", gdb.STDERR)
                return False

            return self.add_files(argv[1:])

        self.edit(argv)


    def add_files(self, files):
            inf = gdb.selected_inferior()
            if inf.pid != 0 and not self.edit(files):
                gdb.write("Could not add the files %s\n" % files, gdb.STDERR)
                return False

            for f in files:
                self.notifier.add_watch(f)

            return True
        

    def edit(self, paths):
        gdb.write("Building... ", gdb.STDERR);
        path = build(paths, self.builds, self.default_build)
        if not path:
            gdb.write("Failed\n", gdb.STDERR)
            return False
        gdb.write("Done\n");

        if not patch_objfile(path, self.patches, self.families):
            gdb.write("Failed to change {0}\n".format(path), gdb.STDERR)

        return True


    def sigsegv_handler(self):
        cli_out = gdb.execute('p /x $_siginfo._sifields._sigfault.si_addr',
                              False, True)
        segv_addr = int(cli_out.split(' ')[-1], 16)
        self.families.try_patch(segv_addr)
#        if not self.families.try_patch(segv_addr):
#            gdb.execute('signal SIGSEGV') #FIXME: Make gdb crash WTF
        gdb.execute('continue')


    def sigrt_handler(self):
        inf = gdb.selected_inferior()
        self.notifier.cond.acquire()

        if inf.pid != 0:
            res = self.edit(self.modifications)
            if res:
                # Empty the modifications
                while len(self.modifications) > 0:
                    f = self.modifications.pop()
#                    self.notifier.i.remove_watch(f)
#                    self.notifier.i.add_watch(f)

        self.notifier.cond.notify()
        self.notifier.cond.release()

        return res


    def test(self):
        self.families.print()


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
            elif event.stop_signal == stop_handler.sac.notifier.sigrt_str:
                stop_handler.sac.sigrt_handler()


    gdb.events.stop.connect(stop_handler)
