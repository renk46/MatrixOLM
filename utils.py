def print_bytes(s, name):
    pt = ""
    for t in s:
        pt += str(t) + " "
    print("%s: %s" % (name, pt))