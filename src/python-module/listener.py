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
#                    dump_objfile(gdb.objfiles())
#                    read_func("foo")
#                    open_shared(0, 0, gdb.selected_inferior(), gdb.selected_frame())
                    for t in threading.enumerate():
                        if t.getName() == "MainThread":
                           pprint(dir(t))
                    clientsocket.close()
                except socket.error:
                    continue


