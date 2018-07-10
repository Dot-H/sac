import gdb

from pprint import pprint

def call(ret_type, func_name, *args):
    if (len(args) == 1): # Edge case of (arg,)
        args = '({})'.format(args[0])

    str_args = f'{args}'
    str_args = str_args.replace('\'', '"') # Putting it as C string
    cmd = f'call ({ret_type}){func_name}{str_args}'
    gdb.write(f"Calling: {cmd}\n", gdb.STDERR)
    cli_out = gdb.execute(cmd, False, True)
    if cli_out:
        return cli_out.split(' ')[-1]
    return None


def sym_addr(funcname):
    sym = gdb.lookup_symbol(funcname)[0]

    if (not sym):
        try:
            res = gdb.execute("p /x (long long){0}".format(funcname), False, True)
            addr_tab = res.split(' ')
            # TODO Check for function name matching
            addr = int(addr_tab[-1], 16)
            return addr
        except (gdb.error, ValueError):
            return None

    addr = sym.value()
    return int(addr.address)
