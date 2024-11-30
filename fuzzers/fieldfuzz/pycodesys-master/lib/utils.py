import string


def hexdump(src, length=16):
    DISPLAY = string.digits + string.letters + string.punctuation
    FILTER = ''.join(((x if x in DISPLAY else '.') for x in map(chr, range(256))))
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        if len(hex) > 24:
            hex = "%s %s" % (hex[:24], hex[24:])
        printable = ''.join(["%s" % FILTER[ord(x)] for x in chars])
        lines.append("%08x:  %-*s  %s\n" % (c, length * 3, hex, printable))
    return ''.join(lines)
#
#
# def dump(title, data):
#     print
#     '--- [ %s ] --- ' % (title)
#     print
#     hexdump(data)


def recvall(sock, n):
    data = ''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def pretty_format_tagsdict(tagsdict):
    outstr=''

    for k in tagsdict:
        # Recursive
        if type(tagsdict[k]) is dict:
            out_value = pretty_format_tagsdict(tagsdict[k])
            out_key = hex(k)+">>"
        elif type(tagsdict[k]) is str:
            out_value = tagsdict[k].encode('hex')
            out_key = hex(k)
        else:
            out_value = 'unknown type'
        outstr += '[' + out_key + '] ' + out_value+' '
    return outstr


def pretty_format_tagslist(tagslist):
    outstr = ''
    for dct in tagslist:
        outstr += pretty_format_tagsdict(dct)
    return outstr


