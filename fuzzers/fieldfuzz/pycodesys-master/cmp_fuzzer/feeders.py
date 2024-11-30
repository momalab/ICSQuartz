import os
from struct import pack
# import pyradamsa

from lib.layers import s_tag, layer7


class CmpFeeder:
    cds = None

    def __init__(self, cds=cds):
        self.cds = cds
        # self.rad = None
        # self.rad = pyradamsa.Radamsa(seed=0)

    def fuz_plcshell(self):
        if not self.cds.sess_id:
            exit('[-] Login to Device first')

        service_id = 0x11  # CmpPlcShell
        payload_len = 200

        command = os.urandom(payload_len)

        tag1 = "\x11\x84\x80\x00" + pack("<I", self.cds.sess_id)
        tag2 = "\x13\x84\x80\x00\x00\x00\x00\x00"
        data = tag1 + tag2 + s_tag(0x10, command + '\x00\x00\x00')
        mL7 = layer7(service_id, 0x1, self.cds.sess_id, data)
        self.cds.send_layer7(mL7)
        tags = self.cds.recv_layer7()

    def fuz_cmpdevice(self):
        if not self.cds.sess_id:
            exit('[-] Login to Device first')

        service_id = 0x01  # CmpDevice
        payload_len = 45

        command = os.urandom(payload_len)

        data = s_tag(0x58, command)

        L7 = layer7(0x01, 0x09, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()

    def fuz_cmpcoredump(self):
        if not self.cds.sess_id:
            exit('[-] Login to Device first')

        service_id = 0x1f  # CmpCoreDump
        command_id = 0x02

        # payload_len = 4
        # payload = os.urandom(payload_len)
        # payload = "\xa2\xc0\x56\x19"

        data = s_tag(0x2, pack("<I", self.cds.app_sess_id))

        L7 = layer7(service_id, command_id, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags

    def fuz_recordadd(self, payload):
        if not self.cds.sess_id:
            exit('[-] Login to Device first')

        service_id = 0x0f  # CmpTraceMgr
        command_id = 0x0d

        '''
        % 0x40 - packet handle
        % 0x84 record config:
        %     0x21 - var addr flags
        %     0x4e - var mon2 size
        %     0x4d - var mon2 bytecode
        %     0x20 - var name
        %     0x25 - var type
        %     0x26 - var size
        %     0x27 - graph type
        %     0x28 - graph color
        %     0x32 - min warning
        %     0x35 - max warning
        %     0x38 - y axis
        %     0x33,  0x34, 0x36, 0x37 - limits, colors
        '''

        tag_84_contains = \
            "\x21\x84\x80\x00\x01\x02\x00\x00" \
            + s_tag(0x4e, "\x05\x00\x00\x00") \
            + s_tag(0x4d, "\x02\x02\x10\x06\x00\x00\x00\x00") \
            + s_tag(0x20, "\x50\x4c\x43\x5f\x50\x52\x47\x2e\x69\x6e\x70\x75\x74\x00\x00\x00") \
            + s_tag(0x25, "\x02\x00\x00\x00") \
            + s_tag(0x26, "\x02\x00\x00\x00") \
            + "\x27\x84\x80\x00" \
              "\x01\x00\x00\x00\x28\x84\x80\x00\xff\x00\x00\xff\x32\x84\x80\x00" \
              "\x00\x00\x00\x00\x35\x84\x80\x00\x00\x00\x00\x00\x38\x84\x80\x00" \
              "\x00\x00\x00\x00\x33\x84\x80\x00\x00\x00\x00\x00\x34\x84\x80\x00" \
              "\x00\x00\x00\xff\x36\x84\x80\x00\x00\x00\x00\x00\x37\x84\x80\x00" \
              "\x00\x00\xff\xff"

        data = s_tag(0x40, payload) + s_tag(0x84, tag_84_contains)

        L7 = layer7(service_id, command_id, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags

    '''
        [0x10]
            41 70 70 5f 62 66 5f 6d 63 70 79 5f 31 2e 54 72 61 63 65 00 
        [0x16]
            00 00 00 00 
        [0x11]
            41 70 70 5f 62 66 5f 6d 63 70 79 5f 31 00 00 00 
        [0x12]
            4d 61 69 6e 54 61 73 6b 00 00 00 00 
        [0x13]
            01 00 00 00 
        [0x14]
            65 00 00 00 
        [0x15]
            10 00 00 00 
    '''

    def fuz_tracemgr_PacketCreate(self, payload):
        data = s_tag(0x10, "\x41\x70\x70\x5f\x62\x66\x5f\x6d\x63\x70\x79\x5f\x31\x2e\x54\x72\x61\x63\x65\x00") \
               + s_tag(0x16, "\x00\x00\x00\x00") \
               + s_tag(0x11, "\x41\x70\x70\x5f\x62\x66\x5f\x6d\x63\x70\x79\x5f\x31\x00\x00\x00") \
               + s_tag(0x12, "\x4d\x61\x69\x6e\x54\x61\x73\x6b\x00\x00\x00\x00") \
               + s_tag(0x13, "\x01\x00\x00\x00") \
               + s_tag(0x14, "\x65\x00\x00\x00") \
               + s_tag(0x15, "\x10\x00\x00\x00")
        L7 = layer7(0x0f, 0x02, self.cds.sess_id, data)

        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags


    '''
    0x40 - packet handle (4 bytes)
    '''

    def fuz_tracemgr_PacketClose(self, payload):
        data = s_tag(0x40, payload)
        L7 = layer7(0x0f, 0x06, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags


    '''
    0x40 - packet handle (4 bytes)
    '''

    def fuz_tracemgr_PacketComplete(self, payload):
        data = s_tag(0x40, payload)
        L7 = layer7(0x0f, 0x04, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags


    '''
    0x40 - packet handle (4 bytes)
    '''


    def fuz_tracemgr_PacketStart(self, payload):
        data = s_tag(0x40, payload)
        L7 = layer7(0x0f, 0x0a, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags


    '''
    0x40 - packet handle (4 bytes)
    0x4a - 4 bytes
    '''


    def fuz_tracemgr_PacketRead(self, payload):
        data = s_tag(0x40, payload) + s_tag(0x4a, "\x00\x00\x00\x00")
        L7 = layer7(0x0f, 0x07, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags


    '''
    0x40 - packet handle (4 bytes)
    '''


    def fuz_tracemgr_PacketStop(self, payload):
        data = s_tag(0x40, payload)
        L7 = layer7(0x0f, 0x0b, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags


    '''
    0x40 - packet handle (4 bytes)
    '''


    def fuz_tracemgr_PacketGetConfig(self, payload):
        data = s_tag(0x40, payload)
        L7 = layer7(0x0f, 0x09, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags


    '''
    0x10 - 20 bytes ASCII:  "App_bf_mcpy_1.Trace"
    '''


    def fuz_tracemgr_PacketOpen(self, payload):
        data = s_tag(0x10, "\x10\x94\x80\x00\x41\x70\x70\x5f\x62\x66\x5f\x6d\x63\x70\x79\x5f" \
                        "\x31\x2e\x54\x72\x61\x63\x65\x00")
        L7 = layer7(0x0f, 0x05, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags


    '''
    Empty tag input
    '''


    def fuz_tracemgr_PacketReadList(self, payload):
        data = ""
        L7 = layer7(0x0f, 0x01, self.cds.sess_id, data)
        self.cds.send_layer7(L7)
        tags = self.cds.recv_layer7()
        return tags
