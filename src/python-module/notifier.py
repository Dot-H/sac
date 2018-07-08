import gdb
import inotify.adapters
import inotify.constants
import os
import signal
import threading

'''
When modifying into vim, vim raises a combo:
IN_MOVE_SELF, IN_ATTRIB, IN_DELETE_SELF, IN_IGNORED
making inotify stop watching the files. We must therefore restart
inotify and re-add all the files.
'''

class Notifier(threading.Thread):
    def __init__(self, modifications):
        threading.Thread.__init__(self)
        self.cond = threading.Condition()
        self.stoprequest = threading.Event()

        self.i = inotify.adapters.Inotify()
        self.i_rst = False
        self.watches = set() # Has to store it here because of the vim bug

        self.modifications = modifications # Must be a set of string
        self.sigrt = signal.SIGRTMIN
        self.sigrt_str = 'SIG{}'.format(self.sigrt)

        # Stop when the main thread stops
        self.setDaemon(True)


    def run(self):
        while True:
            for event in self.i.event_gen():
                self.cond.acquire()

                if not event:
                    if len(self.modifications) > 0:
                        inf = gdb.selected_inferior()
                        os.kill(inf.pid, self.sigrt)
                        self.cond.wait()

                    if self.i_rst:
                        self.restart_inotify()
                        self.i_rst = False
                        break

                elif event:
                    (_, type_names, path, filename) = event
#        gdb.write("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}\n".format(
#                              path, filename, type_names), gdb.STDERR)
                    if type_names == ['IN_MODIFY'] or \
                       type_names == ['IN_MOVE_SELF']:
                        self.modifications.add(path)
                    elif type_names == ['IN_IGNORED'] or \
                         type_names == ['IN_MOVE_SELF']:
                        self.i_rst = True

                self.cond.release()



    def add_watch(self, path, mask=inotify.constants.IN_ALL_EVENTS):
        if path in self.watches:
            return

        self.watches.add(path)
        self.i.add_watch(path, mask)


    def restart_inotify(self):
        del(self.i)
        self.i = inotify.adapters.Inotify()
        for f in self.watches:
            self.i.add_watch(f)
