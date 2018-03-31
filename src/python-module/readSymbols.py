import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def process_file(filename):
    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        symtab_name = '.symtab'
        symtab = elffile.get_section_by_name(symtab_name)
        if not isinstance(symtab, SymbolTableSection):
            print('The file has no %s section' % symtab_name)
            return

        for symbol in symtab.iter_symbols():
            if (symbol.entry['st_info']['type'] == 'STT_FUNC' or
                symbol.entry['st_info']['type'] == 'STT_OBJECT'):
                print(' Symbol %s' % symbol.name)
                for entry in symbol.entry:
                    print(symbol.entry[entry])

if __name__ == '__main__':
    if (len(sys.argv) != 2):
        print('Usage: python elf_symbols_exe64.py FILENAME')

    process_file(sys.argv[1])
