import pprint

def rmWhitespaces(string):
    idx = 0
    while string[idx] == ' ':
        idx += 1

    return string[idx:]

def parseSac(filename, builds):
    with open(filename, "r") as f:
        lines = f.readlines()
        for line in lines:
            if line[-1] == '\n':
                line = line[:-1]

            tokens = line.split(',')
            builds[tokens[0]] = rmWhitespaces(tokens[1]).split(' ')

    pprint.pprint(builds)
