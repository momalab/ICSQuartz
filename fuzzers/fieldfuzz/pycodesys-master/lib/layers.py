import sys, socket, random, string, binascii, argparse

from utils import *
from pwn import *
from struct import pack, unpack, unpack_from
import logging

''' 
L2 
'''


def send_block_driver_tcp(s, data):
    # data is L2+L3 req
    pdu = pack('<II', 0xe8170100, len(data) + 8) + data
    try:
        s.send(pdu)
        return True
    except Exception as e:
        #print('[-] send_block_driver_tcp failed. restart runtime?')
        return False

def recv_block_driver_tcp(s):
    data = ''
    # Read 0x8-byte header
    try:
        data = recvall(s, 0x8)

        # Parse header
        (magic, size) = unpack('<II', data)

        if magic != 0xe8170100:
            raise ValueError('Invalid magic number.')

        # Get data if any
        if size:
            data = recvall(s, size - 8)
        # data is L2+L3 res
        return True, data
    except Exception as e:
        #print('[-] recv_block_driver_tcp failed. restart runtime?')
        return False, None


''' 
L3 
'''


def layer3(service, data, sender='\x00' * 8, receiver='\x00' * 6):
    slrl = ((len(sender) / 2) << 4) | ((len(receiver) / 2) & 0xf)
    hc = 13  # Hop count
    hl = 3  # Offset (in words) to receiver addr
    b2 = ((hc << 3) & 0xf8) | (hl & 0x7)

    pri = 1  # Packet priority; 0 low, 1 normal, 2 high, 3 emergency
    sr = 0  # SignalRouter bit; set by router
    addr_type = 0  # Address type; 0 = direct/absolute address; 1 = relative
    max_blk_len = 0  # Max blk len: compute as (x+1)*32
    msg_id = 0

    b3 = ((pri << 6) & 0xc0) | ((sr << 5) & 0x20)
    b3 |= ((addr_type << 4) & 0x10) | (max_blk_len & 0xf)

    pdu = pack('BBBBBB', 0xc5, b2, b3, service, msg_id, slrl)
    pdu += receiver
    pdu += sender

    if len(pdu) % 4:
        pdu += '\x00' * (4 - len(pdu) % 4)

    pdu += data  # Service/L4 data

    return pdu


''' 
L4 
'''

''' Only support type 1 (ack and send data) '''
def layer4(chan, blk, ack, flags, data):
    pdu = '\x01'  # ACK and send data
    pdu += pack('<BHII', flags, chan, blk, ack)
    pdu += data  # Layer 7 data

    return pdu


''' 
Layer4 Server Meta request(NetServerHandleMetaRequest) 

command_id | flags | version | checksum | cmd_payload   |

0xc3       |     0 |  0x0101 |  0x2222  |               |
'''

def layer4_meta(cmd, cmd_payload):
    cmd |= 0xC0
    flags = 0
    version = 0x0101
    header = pack('<BBH', cmd, flags, version)
    checksum=binascii.crc32(header + '\x00\x00\x00\x00' + cmd_payload)
    rawL4 =  header + pack('<i', checksum) + cmd_payload
    return rawL4


def layer4_meta2(cmd, cmd_payload):
    flags = 0x00
    version = 0x0101
    header = pack('<BBH', cmd, flags, version)
    checksum=binascii.crc32(header + '\x00\x00\x00\x00' + cmd_payload)
    rawL4 =  header + pack('<i', checksum) + cmd_payload
    return rawL4





def dissect_l4(L3):
    try:
        hdr_len = ord(L3[1]) & 0x7
        slrl = (ord(L3[5]) >> 4) | (ord(L3[5]) & 0xf)
        pos = hdr_len + slrl
        pos = pos + (pos % 2)
        pos = pos * 2

        return L3[pos:]
    except Exception as e:
        print ('[-] dissect_l4 eror: %s' % str(e))
        return None


''' 
L7
'''


def layer7(service_group, command_id, sess_id, data):
    hdr = pack('<HHII', service_group, command_id, sess_id, len(data))
    hdr += pack('<HH', 0, 0)

    pdu = pack('<HH', 0xcd55, len(hdr))
    pdu += hdr
    pdu += data  # Layer7 body

    pdu = pack('<Ii', len(pdu), binascii.crc32(pdu)) + pdu

    #tagstr = pretty_format_tagsdict(parse_tags_to_dict(data))

    #print('\n\n\t\t\t[Built Layer7 for Service 0x%x Cmd 0x%x, Tags: %s]\n\n' % (service_group, command_id, tagstr)),


    return pdu


def dissect_l7(L4):
    return L4[20:]


def dissect_l7_body(data, layer):
    if layer == 3:
        L4 = dissect_l4(data)
        L7 = dissect_l7(L4)
    elif layer == 4:
        L7 = dissect_l7(data)
    elif layer == 7:
        L7 = data
    else:
        raise ValueError('Invalid layer')

    (proto, hdr_size,) = unpack_from('<HH', L7)
    if proto != 0xcd55:
        raise ValueError('Invalid layer 7 protocol')

    return L7[(4 + hdr_size):]


''' 
L7 Tags
'''


def s_tag_encode_int(val):
    # 7 bits
    if (val <= 0x7f):
        return pack('B', val)
    # 14 bits
    elif (val <= 0x3fff):
        return pack('BB', (val & 0x7f) | 0x80, (val >> 7) & 0x7f)
    # 21 bits
    elif (val <= 0x1fffff):
        return pack('BBB',
                    (val & 0x7f) | 0x80,
                    (val >> 7) | 0x80,
                    (val >> 14) & 0x7f
                    )
    # 28 bits
    elif (val <= 0xfffffff):
        return pack('BBBB'
                    (val & 0x7f) | 0x80,
                    (val >> 7) | 0x80,
                    (val >> 14) | 0x80,
                    (val >> 21) & 0x7f
                    )
    # TODO: encode larger int
    else:
        raise ValueError('Value too big to encode.')


def s_tag_decode_int(data, pos):
    max = 0xffffffff
    lshift = 0
    dlen = len(data)

    val = 0
    t = 0
    while True:
        if (pos >= dlen):
            return None

        t = ord(data[pos])
        if ((t & 0x7f) > max):
            return None

        val += ((t & 0x7f) << lshift)
        pos += 1
        lshift += 7
        max = max >> 7

        if (t & 0x80 == 0):
            break

    return [val, pos]


def parse_tag_to_list(data, pos):
    # Tag id
    ret = s_tag_decode_int(data, pos)
    # print(ret)
    if ret == None:
        return None
    id = ret[0]
    pos = ret[1]

    # Tag length
    ret = s_tag_decode_int(data, pos)
    # print(ret)
    if ret == None:
        return None

    size = ret[0]
    pos = ret[1]

    # Tag  value
    value = data[pos:pos + size]

    # [+] stop
    if (len(value) < size) or (len(value) == 0):
        return None

    pos += size

    return [id, value, pos]

# Screws up if duplicate tag IDs
def parse_tags_to_dict(data):
    dlen = len(data)
    pos = 0
    tags = {}
    while pos < dlen:
        ret = parse_tag_to_list(data, pos)
        if ret == None:
            return None
        id = ret[0]
        value = ret[1]
        pos = ret[2]
        tags[id] = value

    return tags

# v fixed
def parse_tags_to_list(data):
    dlen = len(data)
    pos = 0
    tags = []
    while pos < dlen:
        ret = parse_tag_to_list(data, pos)
        if ret == None:
            return None
        id = ret[0]
        value = ret[1]
        pos = ret[2]
        tags.append((id, value))

    return tags

# v fixed
def pretty_format_tags_recursive(data, i=0, log=""):
    res = parse_tags_to_list(data)
    if res is None:
        data_hex = ' '.join('{:02x}'.format(ord(c)) for c in data)
        log += '{}'.format(data_hex)
        return log
    for id, value in res:
        log += '\n{}[{}] '.format("----"*i, hex(id))
        log = pretty_format_tags_recursive(value, i+1, log)
    return log


# def parse_tags_to_dict_recursive(rawdata):
#     dct = parse_tags_to_dict(rawdata)
#
#     for tag in dct:
#         for nested_id in [0x81, 0x82, 0x5]:
#             if nested_id in tag:
#                 #print('Deeper: %s' % pretty_format_tagsdict(dct))
#                 nested_parsed = parse_tags_to_dict_recursive(dct[nested_id])
#
#                 # Rewrite
#                 if nested_parsed:
#                     dct[nested_id] = nested_parsed
#     return dct


def s_tag(id, value):
    tag = s_tag_encode_int(id)  # Tag id
    tag += s_tag_encode_int(len(value))  # Tag length
    tag += value  # Tag value

    return tag
