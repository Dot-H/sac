from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def read_symbols(path):
    ret = {}
    with open(path, "rb") as f:
        elffile = ELFFile(f)

        symtab_name = '.symtab'
        symtab = elffile.get_section_by_name(symtab_name)
        if not isinstance(symtab, SymbolTableSection):
            print('The file has no %s section' % symtab_name)
            return

        for symbol in symtab.iter_symbols():
            if (symbol.entry['st_info']['type'] == 'STT_FUNC' or
               symbol.entry['st_info']['type'] == 'STT_OBJECT'):
                ret[symbol.name] = symbol.entry

    return ret
