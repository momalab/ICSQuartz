#! /usr/bin/env python2

from pwnlib.util.fiddling import hexdump
from lib.pycodesys import s_tag, parse_tag_to_list, pretty_format_tags_recursive




'''
Encode / Decode L7 tags
'''



'''

\xa8\x58 bytecode? offset? id?

\x09\x04\x04\x00\x00" type?
'''

#write

temp="\x01\x94\x80\x00\xd8\xc2\xe6\x8e\xec\x4e\x23\x55\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x03\xa8\x80\x00\x00\x00\x02\x00" \
"\x00\x00"+"\xba\xba"+"\x1b\x00\x15\x0c\x00\x02" + "\xa8\x58" + "\x06\x00\x17\x0c" \
"\x09\x04\x1b\x06\x00\x01\x00\x00\x17\x04\x09\x04\x17\x08" + "\x09\x04\x04\x00\x00" + "\x00"

# read




t1="\x01\x94\x80\x00\xd8\xc2\xe6\x8e\xec\x4e\x23\x55\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x03\xa8\x80\x00\x00\x00\x02\x00" \
"\x00\x00\xba\xba\x1b\x00\x15\x0c\x00\x02 \xa8\x58\x06\x00\x17\x0c" \
"\x09\x04\x1b\x06\x00\x01\x00\x00\x17\x04\x09\x04\x17\x08\x09\x04" \
"\x04\x00\x00\x00"

t2="\x01\x94\x80\x00\xd5\xf7\x4b\xcd\x93\xf9\x84\xd7\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x03\xcc\x80\x00\x00\x00\x02\x00" \
"\x00\x00\xbb\xbb\x1b\x00\x15\x0c\x00\x02 \x28\x39 \x06\x00 \x17\x0c" \
"\x09\x04\x1b\x06\x00\x01\x00\x00\x17\x04\x09\x04\x17\x08\x09\x04" \
"\x04\x00\x00\x02\x00\x00\x00\xbb\xbb\x1b\x00\x15\x0c\x00\x02\x24" \
"\x39\x06\x00\x17\x0c\x09\x04\x1b\x06\x00\x01\x00\x00\x17\x04\x09" \
"\x04\x17\x08\x09\x04\x04\x00\x00"

t3="\x01\x94\x80\x00\xb8\x02\x4f\x7d\xe8\x32\x8d\x04\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x03\xf0\x80\x00\x00\x00\x02\x00" \
"\x00\x00\x00\x00\x1b\x00\x15\x0c\x00\x02\x28\x39\x06\x00\x17\x0c" \
"\x09\x04\x1b\x06\x00\x01\x00\x00\x17\x04\x09\x04\x17\x08\x09\x04" \
"\x04\x00\x00\x02\x00\x00\x00\x00\x00\x1b\x00\x15\x0c\x00\x02\x24" \
"\x39\x06\x00\x17\x0c\x09\x04\x1b\x06\x00\x01\x00\x00\x17\x04\x09" \
"\x04\x17\x08\x09\x04\x04\x00\x00\x02\x00\x00\x00\x00\x00\x1b\x00" \
"\x15\x0c\x00\x02\x26\x39\x06\x00\x17\x0c\x09\x04\x1b\x06\x00\x01" \
"\x00\x00\x17\x04\x09\x04\x17\x08\x09\x04\x04\x00"

multitags = "\x81\x01\xa0\x01\x82\x01\xa4\x00\x01\x02\x01\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
                   "\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xac\x39\x06" \
                   "\x00\x00\x00\x00\x82\x01\xa4\x00" \
                   "\x01\x02\x02\x00\x02\x84\x80\x00" \
                   "\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
                   "\x05\x88\x80\x00\x02\xc4\x39\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
                   "\x01\x02\x03\x00\x02\x84\x80\x00\x02\x00\x00\x00\x03\x84\x80\x00" \
                   "\x03\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xcc\x3a\x06" \
                   "\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x04\x00\x02\x84\x80\x00" \
                   "\x04\x00\x00\x00\x03\x84\x80\x00\x0c\x00\x00\x00\x04\x02\x05\x00" \
                   "\x05\x88\x80\x00\x02\xa8\x58\x06\x00\x00\x00\x00"


#multi="\x01\x94\x80\x00\x76\x2c\x30\xa8\xec\x4e\x23\x55\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x81\x01\xe0\x03\x82\x01\xa4\x00" \
"\x01\x02\x01\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x9c\x39\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x02\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xb4\x39\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x03\x00\x02\x84\x80\x00\x02\x00\x00\x00\x03\x84\x80\x00" \
"\x03\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xbc\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x04\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xc8\x3a\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x05\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xb8\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x06\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x9c\x3a\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x07\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xa0\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x08\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xa4\x3a\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x09\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xa8\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x0a\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x08\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xac\x3a\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x0b\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00"\
+ "\x08\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xb0\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x0c\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x08\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xb4\x3a\x06\x00\x00\x00\x00"

# many BYTE

multi= "\x01\x94\x80\x00\x17\xeb\x0d\xb9\x37\xe1\x08\x44\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x81\x01\xc0\x07\x82\x01\xa4\x00" \
"\x01\x02\x01\x00\x02\x84\x80\x00\x02\x00\x00\x00\x03\x84\x80\x00" \
"\x03\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xbc\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x02\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xc8\x3a\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x03\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xb8\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x04\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x9c\x3a\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x05\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xa0\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x06\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xa4\x3a\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x07\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xa8\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x08\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x08\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xac\x3a\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x09\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x08\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xb0\x3a\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x0a\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x08\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xb4\x3a\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x0b\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
+ \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x9c\x39\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x0c\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xb4\x39\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x0d\x00\x02\x84\x80\x00\x01\x00\x00\x00\x03\x84\x80\x00" \
"\x02\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x28\x39\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x0e\x00\x02\x84\x80\x00" \
"\x01\x00\x00\x00\x03\x84\x80\x00\x02\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x29\x39\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x0f\x00\x02\x84\x80\x00\x01\x00\x00\x00\x03\x84\x80\x00" \
"\x02\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x8f\x39\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x10\x00\x02\x84\x80\x00" \
"\x01\x00\x00\x00\x03\x84\x80\x00\x02\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x1a\x3f\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x11\x00\x02\x84\x80\x00\x01\x00\x00\x00\x03\x84\x80\x00" \
"\x02\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xd9\x51\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x12\x00\x02\x84\x80\x00" \
"\x01\x00\x00\x00\x03\x84\x80\x00\x02\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x8d\x39\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x13\x00\x02\x84\x80\x00\x01\x00\x00\x00\x03\x84\x80\x00" \
"\x02\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\xb6\x37\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x14\x00\x02\x84\x80\x00" \
"\x01\x00\x00\x00\x03\x84\x80\x00\x02\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\xda\x51\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x15\x00\x02\x84\x80\x00\x01\x00\x00\x00\x03\x84\x80\x00" \
"\x02\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x1b\x3f\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x16\x00\x02\x84\x80\x00" \
"\x01\x00\x00\x00\x03\x84\x80\x00\x02\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x8e\x39\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x17\x00\x02\x84\x80\x00\x01\x00\x00\x00" \
+ \
"\x03\x84\x80\x00\x02\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00" \
"\x02\xd8\x51\x06\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x18\x00" \
"\x02\x84\x80\x00\x01\x00\x00\x00\x03\x84\x80\x00\x02\x00\x00\x00" \
"\x04\x02\x05\x00\x05\x88\x80\x00\x02\xdb\x51\x06\x00\x00\x00\x00"


temp="\x01\x94\x80\x00\x58\x37\x73\x9d\x0f\xe9\x7e\x9a\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x81\x01\x88\x04\x82\x01\xa4\x00" \
"\x01\x02\x01\x00\x02\x84\x80\x00\x02\x00\x00\x00\x03\x84\x80\x00" \
"\x03\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x28\x38\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x02\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x34\x38\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x03\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x24\x38\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x04\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x08\x38\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x05\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x0c\x38\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x06\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x04\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x10\x38\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x07\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x14\x38\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x08\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x08\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x18\x38\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x09\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x08\x00\x00\x00\x04\x02\x05\x00\x05\x88\x80\x00\x02\x1c\x38\x06" \
"\x00\x00\x00\x00\x82\x01\xa4\x00\x01\x02\x0a\x00\x02\x84\x80\x00" \
"\x04\x00\x00\x00\x03\x84\x80\x00\x08\x00\x00\x00\x04\x02\x05\x00" \
"\x05\x88\x80\x00\x02\x20\x38\x06\x00\x00\x00\x00\x82\x01\xa4\x00" \
"\x01\x02\x0b\x00\x02\x84\x80\x00\x04\x00\x00\x00\x03\x84\x80\x00" \
"\x04\x00\x00\x00\x04\x02\x05\x00"


temp="\x01\x94\x80\x00\x51\x70\xa0\x38\xe4\x46\x94\xa9\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x03\xa8\x80\x00\x00\x00\x02\x00" \
"\x00\x00\x80\x0d\x1b\x00\x15\x0c\x00\x02\x02\x10\x06\x00\x17\x0c" \
"\x09\x04\x1b\x06\x00\x01\x00\x00\x17\x04\x09\x04\x17\x08\x09\x04" \
"\x04\x00\x00\x00"

print(pretty_format_tags_recursive(temp))









