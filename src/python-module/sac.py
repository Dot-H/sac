#!/usr/bin/python

import gdb
import socket
import threading
from pprint import pprint
import sys

sac = None

def dump_objfile(objfiles):
    for f in objfiles:
        if f.filename:
            gdb.write(f.filename + '\n')
            gdb.write(f.build_id + '\n')
        else:
            gdb.write("no filename\n", gdb.stderr)

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
                    clientsocket.close()
                except socket.error:
                    continue


class SacCommand (gdb.Command):
    "Command to update the code in real time."
    
    def __init__(self):
        super (SacCommand, self).__init__("sac", gdb.COMMAND_USER,
                                          gdb.COMPLETE_NONE)
        self.listener = Listener(1, "FileListener", 1)

    def invoke(self, arg, from_tty):
        self.listener.start() 

sac = SacCommand()
