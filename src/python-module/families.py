import bisect as bs
import gdb

from collections import defaultdict
from libInjection import get_injection_addr, chg_pg_prot
from resource import getpagesize

pg_size = getpagesize()

# FIXME: Translate to families. The idea is the same.
'''
    Browser refers to an object symbol linked to all the objects
    present in the address space who refers to the same symbol.

    When opening a shared library which contains a global object,
    the refering symbol gets a new version but the old versions
    are still present in some part of the code.
    Therefore, if a global symbol who's been patched is modified,
    we need to modify all its versions.

    The class Browser is here to do that. All the global object
    symbol patched are in the SacCommand.families dictionnary and
    when a symbol need to be patched, it patches all the browser
    of the family corresponding to that symbol.
'''
class Families(object):
    def __init__(self):
        self._families  = defaultdict(list) # Dict of list of SymbolObject
        self._locations = defaultdict(list) # Dict of list of (symbol, SymbolObject)


    def insert(self, lib_path, symbol, obj):
        if not symbol in self._families:
            self._families[symbol] = [obj]
            self._locations[lib_path] = [(symbol, obj)]
            return True

        # Search for the insertion index
        a = self._families[symbol]
        idx = bs.bisect_left(a, obj)
        if idx != len(a) and obj == a[idx]:
            return True # already present
        inf = gdb.selected_inferior()

        # Update the new object with the current value of the family
        if len(a) > 0:
            new_value = a[0].get_value(inf)
            obj.set_value(inf, new_value)

        # Insert the new object into the family and remove its write protection
        a.insert(idx, obj)
        if not obj.chg_pg_prot(inf, False):
            return False # Failed to change page protection

        self._locations[lib_path].append((symbol, obj))
        return True


    def remove(self, symbol, obj):
        a = self._families[symbol]
        idx = bs.bisect_left(a, obj)
        if idx != len(a) and a[idx] == obj:
            # Restore the write protection and remove the object from the family
            obj = a.pop(idx)
            return obj.chg_pg_prot(gdb.selected_inferior(), True)

        return True


    def try_patch(self, addr):
        srch_tmp = SymboleObject(addr, 0)
#        gdb.write("Searching corresponding object...", gdb.STDERR)
        for symbol, family in self._families.items():
            idx = bs.bisect_left(family, srch_tmp)
            if idx == len(family) or not family[idx].is_addr_in(addr):
                continue # Not in this family

#            gdb.write("Found\nPatching %s..." % symbol, gdb.STDERR)
            gdb.write("Patching family '%s'... " % symbol, gdb.STDERR)
            inf = gdb.selected_inferior()

            # Let faulting instruction being executed then get new value
            # TODO: Try to read the value wich should be written instead and
            #       write it ourself instead of putting back the permissions
            family[idx].chg_pg_prot(inf, True)
            gdb.execute('si', False, True)
            family[idx].chg_pg_prot(inf, False)
            new_value = family[idx].get_value(inf)

            # Patching the whole family
            for obj in family[:idx] + family[idx+1:]:
                obj.set_value(inf, new_value)

            gdb.write("Done\n", gdb.STDERR)

            return True

        gdb.write("Not found\n", gdb.STDERR)
        return False


    def restore_shared_lib(self, lib_path):
        sym_obj_list = self._locations[lib_path]
        for symbol, obj in sym_obj_list:
            if not self.remove(symbol, obj):
                gdb.write("Failed to restore page protection for %s"
                          % symbol, gdb.STDERR)


    def print(self):
        for sym, family in self._families.items():
            print('%s { ' % sym, end='', flush=False)
            for obj in family:
                obj.print(' ')
                print(' ', end='', flush=False)
            print('}', flush=True)


class SymboleObject(object):
    def __init__(self, addr, size):
        self.size = size
        self.addr = addr

    def __le__(self, other): # For x <= y
        return self.addr < other.addr

    def __eq__(self, other): # For x == y
        return self.addr == other.addr                              

    def __ne__(self, other): # For x != y OR x <> y
        return self.addr != other.addr

    def __gt__(self, other): # For x > y
        return self.addr > other.addr

    def __ge__(self, other): # For x >= y
        return self.addr >= other.addr

    def pg_addr(self):
        return self.addr & ~(pg_size - 1) # Gets lower multiple of 4096

    def get_value(self, inf):
        return inf.read_memory(self.addr, self.size)

    def set_value(self, inf, new_value):
        inf.write_memory(self.addr, new_value)

    def chg_pg_prot(self, inf, has_write_prot):
        return chg_pg_prot(get_injection_addr() + 0x10, inf,
                           self.pg_addr(), has_write_prot) 

    def is_addr_in(self, addr):
        return addr >= self.addr and addr < self.addr + self.size

    def print(self, end='\n', flush=True):
        print("[{0}: {1}]".format(hex(self.addr), self.size),
              end=end, flush=flush)
