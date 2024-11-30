# /usr/bin/env python2
import struct
import sys, socket, random, string, binascii, argparse

import ipdb

from utils import *
from .layers import *
from pwn import *
from struct import pack, unpack, unpack_from
import os

"""
Types
"""

CDS_BOOL = 0x0
CDS_BYTE = 0x2
CDS_WORD = 0x3
CDS_INT = 0x7
CDS_UDINT = 0x0C
# CDS_STRING = 0x0f
CDS_STRING = 0x10
CDS_WSTRING = 0x11
# Corban
CDS_REAL = 0x08
CDS_LREAL = 0x09
CDS_LREAL_ARRAY_2 = 0x0A
CDS_LREAL_ARRAY_4 = 0x0B
CDS_LREAL_ARRAY_7 = 0x12
CDS_LREAL_ARRAY_8 = 0x0D
CDS_LREAL_ARRAY_21 = 0x0E
CDS_LREAL_ARRAY_41 = 0x0F

# https://help.codesys.com/webapp/_cds_datatype_wstring;product=codesys;version=3.5.13.0
# RTS_WCHAR size 16 unicode prefix wsz
# https://help.codesys.com/webapp/_cds_datatype_string;product=codesys;version=3.5.13.0
# RTS_CSTRING size 8 ascii prefix sz
#
# The wsz and sz prefixes are for pointers to characters or arrays of characters.
#
# Examples:
#
# RTS_WCHAR * wszName;
# RTS_CSTRING szName[];


CDS_TYPE_IDS = {
    "CDS_BOOL": 0x0,
    "CDS_BYTE": 0x2,
    "CDS_WORD": 0x3,
    "CDS_INT": 0x7,
    "CDS_UDINT": 0x0C,
    "CDS_STRING": 0x10,
    "CDS_WSTRING": 0x11,
    # Added by Corban
    "CDS_REAL": 0x08,
    "CDS_LREAL": 0x09,
    "CDS_LREAL_ARRAY_2": 0x0A,
    "CDS_LREAL_ARRAY_4": 0x0B,
    "CDS_LREAL_ARRAY_7": 0x12,
    "CDS_LREAL_ARRAY_8": 0x0D,
    "CDS_LREAL_ARRAY_21": 0x0E,
    "CDS_LREAL_ARRAY_41": 0x0F,
}


"""
Sizes
"""
CDS_SIZE = {
    CDS_BOOL: 1,
    CDS_BYTE: 1,
    CDS_WORD: 2,
    CDS_INT: 2,
    CDS_UDINT: 4,
    CDS_STRING: 80,
    CDS_WSTRING: 160,
    # Corban
    CDS_REAL: 4,
    CDS_LREAL: 8,
    CDS_LREAL_ARRAY_2: 2 * 8,
    CDS_LREAL_ARRAY_4: 4 * 8,
    CDS_LREAL_ARRAY_7: 7 * 8,
    CDS_LREAL_ARRAY_8: 8 * 8,
    CDS_LREAL_ARRAY_21: 21 * 8,
    CDS_LREAL_ARRAY_41: 41 * 8,
}


class VMeta:
    def __init__(self, type, offset, name="", bcode=None):
        self.name = name
        self.type = type
        if type not in CDS_SIZE:
            exit("VMeta: Unknown size for type " + str(hex(type)))
        if not offset > 0:
            exit("VMeta: offset cannot be negative")
        self.size = CDS_SIZE[type]
        self.offset = offset


class CodesysNode:
    blk = 1
    ack = 0
    chan_id = 0
    sess_id = 0
    app_sess_id = None
    app_sess_id2 = None
    appname = ""
    host = ""
    port = 0
    s = None
    iec_variables = {}
    blk_failure = False
    last_l4 = ""

    def __init__(self, host="softplc", port=11740, verbose=False):
        self.host = host
        self.port = port
        self.verbose = verbose

    """     Open channel    """

    def open_channel(self):
        print("[c] Open Channel")
        message_id = random.randint(1, 0xFFFFFFFF)
        rec_buf_size = 2048000
        payload = pack("<II", message_id, rec_buf_size) + "\x08\x00\x00\x00"

        # 0x40 Channel Service, 0xc3 GET_CHANNEL
        mL3 = layer3(0x40, layer4_meta(cmd=3, cmd_payload=payload))

        send_block_driver_tcp(self.s, mL3)
        st, res = recv_block_driver_tcp(self.s)

        if not st:
            return False

        resL4 = dissect_l4(res)

        if not resL4:
            return False

        # Get reason and new_chan_id
        (
            status,
            new_chan_id,
        ) = unpack_from("<HH", resL4, offset=12)

        if status == 0x1 and new_chan_id == 0xFFFF:
            print("[!] Failed to open channel. Probably exceeded MAX_CHANNELS)")
            self.s.close()
            return False
        elif status != 0x0 or new_chan_id == 0xFFFF or new_chan_id == 0x0:
            print(
                "[!] Failed to open channel. Other error: "
                + str(status)
                + " ("
                + hex(new_chan_id)
                + ")"
            )
            self.s.close()
            # sys.exit(1)
            return False
        else:
            print("[*] Opened channel: " + str(new_chan_id))
            self.chan_id = new_chan_id
            return True

    """     Close channel    """

    def close_channel(self, chan_id=None):
        if not chan_id:
            chan_id = self.chan_id
        print("[c] Close Channel " + str(chan_id) + " (" + hex(chan_id) + ")")

        # Channel ID and reason
        reason = "\x00\x00"
        data = pack("<H", chan_id) + reason

        # 0x40 Channel Service, 0xc4 CLOSE_CHANNEL
        m4 = layer4_meta(cmd=4, cmd_payload=data)
        mL3 = layer3(0x40, m4)

        send_block_driver_tcp(self.s, mL3)
        if chan_id == self.chan_id:
            self.chan_id = None
        print("[*] Closed channel ")

    """     Info channel    """

    def send_keepalive(self):
        print("[c] Send keepalive ")

        # cmd=0x03 + flags=0x80 (resp) + chan_id
        mL4 = "\x03" + "\x00" + pack("<H", self.chan_id)

        # 0x40 ChannelMgr, 0x03 Keepalive
        mL3 = layer3(0x40, mL4)

        send_block_driver_tcp(self.s, mL3)

        print("[*] Sent keepalive ")

    # def send_ack(self):
    #     print('[c] Send ack ')
    #
    #     # cmd=0x02 + flags=0x80 (resp) + chan_id
    #     mL4 = "\x02"+"\x00"+pack('<H', self.chan_id)
    #
    #     # 0x40 ChannelMgr, 0x03 Keepalive
    #     mL3 = layer3(0x40, mL4)
    #
    #     send_block_driver_tcp(self.s, mL3)
    #
    #     print("[*] Sent ack ")

    """    CmpDevice GetTargetIdent    """

    def getTargetident(self):
        # TODO
        print("[c] getTargetident")
        if self.verbose:
            context.log_level = "debug"
        if not self.s:
            self.s = remote(self.host, self.port, typ="tcp")
        # mL7 = "\x55\xcd\x10\x00\x01\x00\x01\x00\x60\x2b\x99\x8b\x10\x00\x00\x00" \
        #      "\x00\x00\x00\x00\x01\x8c\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        #      "\x00\x00\x00\x00"

        # tagdata = "\x01\x8c\x80\x00\x00\x10\x00\x00\x01\x00\x92\x17\x28\x10\x05\x03"

        tagdata = s_tag(0x1, "\x00\x10\x00\x00\x01\x00\x92\x17\x28\x10\x05\x03")

        self.send_layer7(
            layer7(service_group=0x01, command_id=0x01, sess_id=0x0, data=tagdata)
        )
        self.recv_layer7()

        return False

    """    CmpDevice ResetOriginDevice    """

    def resetOriginDevice(self):
        # TODO
        print("[c] resetOriginDevice")
        if self.verbose:
            context.log_level = "debug"
        if not self.s:
            self.s = remote(self.host, self.port, typ="tcp")

        tagdata = ""

        self.send_layer7(
            layer7(service_group=0x01, command_id=0x01, sess_id=0x0, data=tagdata)
        )
        tags = self.recv_layer7()

        if 0x84 not in tags:
            print("[-] s_tag 0x84 not found in response")
            return False

        data = tags[0x84]
        tags = parse_tags_to_dict(data)
        print(pretty_format_tagsdict(tags))
        return True

    """     Connect    """

    def connect(self, existing_chan_id=None):
        if self.verbose:
            print(
                "[c] Connecting to TCP CodesysNode "
                + self.host
                + ":"
                + str(self.port)
                + "..."
            )
            context.log_level = "debug"
        else:
            context.log_level = "CRITICAL"
        try:
            self.s = remote(self.host, self.port, typ="tcp")
            if self.open_channel():
                print("[*] Connected")
                return True
            else:
                return False
        except PwnlibException as e:
            # print(e)
            return False

    def reconnect(self):
        print("[*] Reconnecting")
        if self.verbose:
            context.log_level = "debug"
        if self.s:
            self.s.close()
        connected = False
        while not connected:
            sleep(0.2)
            connected = self.connect()
            # if self.verbose:
            #     print("[*] ... reconnecting: %s" % connected)
        # print('[*] Reconnected')
        self.blk = 1
        self.ack = 0
        self.blk_failure = False

    def loginToDevice(self):
        #
        # Login to Device (Get a session with CmpDevice -> Login)
        #
        print("[c] Login to Device")
        tag_10 = s_tag(0x10, "\x00\x00")
        data = s_tag(0x22, pack("<H", 1)) + s_tag(0x81, tag_10)
        L7 = layer7(service_group=1, command_id=2, sess_id=0x11, data=data)
        self.send_layer7(L7)

        # st, res = recv_block_driver_tcp(self.s)

        # L4 = dissect_l4(res)
        # self.ack = unpack_from('<I', L4, 4)[0]
        # L7_body = dissect_l7_body(L4, 4)
        # tags = parse_tags_to_dict(L7_body)

        tags = self.recv_layer7()

        if 0x82 not in tags:
            print("s_tag 0x82 not found in response")
            self.sess_id = 0
            return False

        data = tags[0x82]
        tags = parse_tags_to_dict(data)

        if not all(k in tags for k in (0x20, 0x21)):
            print("s_tag 0x20 or 0x21 not found in response")
            self.s.close()
            sys.exit(1)

        status = tags[0x20]
        new_sess_id = tags[0x21]

        if len(status) != 2:
            print("Length of status s_tag is not 2 bytes")
            self.s.close()
            sys.exit(1)

        status = unpack("<H", status)[0]
        if status != 0:
            print("Response status not ERR_OK")
            self.s.close()
            sys.exit(1)

        if len(new_sess_id) != 4:
            print("Length of session id s_tag is not 4 bytes")
            self.s.close()
            sys.exit(1)

        print("[*] Got session id: " + new_sess_id.encode("hex"))
        new_sess_id = unpack("<I", new_sess_id)[0]

        print("[*] Logged in")
        self.sess_id = new_sess_id
        return True

    """ Close connection"""

    def disconnect(self):
        if not self.s.sock:
            return
        print("[c] Disconnect")
        context.log_level = "error"

        if self.app_sess_id:
            self.logoutFromApp()

        if self.sess_id:
            self.logoutFromDevice()

        if self.chan_id:
            self.close_channel()

        self.ack = 0
        self.blk = 0

        # Close socket
        self.s.close()
        print("[*] Disconnected")

    """ Send Layer7 without fragmentation """

    def send_layer7(self, l7data):
        if not self.s or not self.s.connected():
            return
        L4 = layer4(self.chan_id, self.blk, self.ack, 0x81, l7data)
        L3 = layer3(64, L4)
        st = send_block_driver_tcp(self.s, L3)
        # If send_block_driver_tcp failed and closed socket
        if not st:
            print("send_layer7 retry here")
            self.blk_failure = True
            self.app_sess_id = None
            self.sess_id = None
            self.chan_id = 0

            # exit()

        if self.verbose:
            print(
                "[Sending L7] [Blk: %d Ack: %d Data: %s ]"
                % (self.blk, self.ack, l7data.encode("hex"))
            )
            pass
        self.blk += 1  # Next block to send
        return self.blk

    """ Receive Layer7 """

    def recv_layer7(self):
        if not self.s or not self.s.connected():
            return []

        checks_left = 5
        while True:
            st, res = recv_block_driver_tcp(self.s)
            # If recv_block_driver_tcp failed and closed socket
            if not st:
                # print('recv_layer7 retry here')
                self.blk_failure = True
                self.app_sess_id = None
                self.sess_id = None
                self.chan_id = 0
                return []

            # Keepalives: Ignoring keepalive as Fix for Ignored packet: c57340400034b032c0a8780100002ddcc0a87880030080cf (Len=24) (L4=030080cf)
            L4 = dissect_l4(res)
            self.last_l4 = L4
            if len(L4) == 4 and L4[0:2] == "\x03\x00":
                keepalive_chan = unpack("<H", L4[2:4])[0]
                if keepalive_chan == self.chan_id:
                    print(
                        "[*] Keepalive for us (Our chan: %s) (Len=%d) (L4=%s)"
                        % (hex(self.chan_id), len(res), L4.encode("hex"))
                    )
                else:
                    print(
                        "[*] Keepalive NOT for us (Our chan: %s) (Len=%d) (L4=%s)"
                        % (hex(self.chan_id), len(res), L4.encode("hex"))
                    )
                # self.s.close()
                # return []
                checks_left -= 1
            elif len(L4) == 32 and L4[0:2] == "\x84\x00":
                print(
                    "[*] Ignore32 (Our chan: %s) (Len=%d) (L4=%s)"
                    % (hex(self.chan_id), len(res), L4.encode("hex"))
                )

            # elif (len(L4) == 8 and L4[0:2]=="\x02\x00"):
            #     print('[*] Keepalive2 (Len=%d) (L4=%s)' % (len(res), L4.encode('hex')))
            #     #self.reconnect()
            #     checks_left -= 1
            else:
                # If valid L4
                try:
                    self.ack = unpack_from("<I", L4, 4)[0]
                    L7_body = dissect_l7_body(L4, 4)
                    tags_dict = parse_tags_to_dict(L7_body)
                    if self.verbose:
                        print(
                            "\n[*] Response tags: "
                            + pretty_format_tagsdict(tags_dict)
                            + "\n"
                        ),
                    return tags_dict
                except Exception as e:
                    print(
                        "[-] Cannot get ACK and tags from incoming L4! Ignored packet: %s (Len=%d) (L4=%s)"
                        % (res.encode("hex"), len(res), L4.encode("hex"))
                    )
            return []

    def recv_layer7_2(self):
        if not self.s or not self.s.connected():
            return []

        checks_left = 5
        while checks_left == checks_left:
            st, res = recv_block_driver_tcp(self.s)
            # If recv_block_driver_tcp failed and closed socket
            if not st:
                print("recv_layer7 retry here")
                self.blk_failure = True
                self.app_sess_id = None
                self.sess_id = None
                self.chan_id = 0
                return []

            # Ignoring keepalive as Fix for Ignored packet: c57340400034b032c0a8780100002ddcc0a87880030080cf (Len=24) (L4=030080cf)
            L4 = dissect_l4(res)
            if len(L4) == 4 and L4[0:2] == "\x03\x00":
                print("[*] Keepalive (Len=%d) (L4=%s)" % (len(res), L4.encode("hex")))
                self.s.close()
                self.connect()
                return []
                checks_left -= 1
            # elif (len(L4) == 8 and L4[0:2]=="\x02\x00"):
            #     print('[*] Keepalive2 (Len=%d) (L4=%s)' % (len(res), L4.encode('hex')))
            #     #self.reconnect()
            #     checks_left -= 1
            else:
                break

        # If valid L4
        try:
            self.ack = unpack_from("<I", L4, 4)[0]
            L7_body = dissect_l7_body(L4, 4)
            tags_dict = parse_tags_to_dict(L7_body)
            if self.verbose:
                print(
                    "\n[*] Response tags: " + pretty_format_tagsdict(tags_dict) + "\n"
                ),
            return tags_dict
        except Exception as e:
            print(
                "[-] Cannot get ACK and tags from incoming L4! Ignored packet: %s (Len=%d) (L4=%s)"
                % (res.encode("hex"), len(res), L4.encode("hex"))
            )
            # import ipdb;ipdb.set_trace()
            return []

    # '''
    # CmpSettings actions
    # '''
    # ''' SettgSetIntValue'''
    # def SettgSetIntValue(sess_id, cmp, key, val):
    #   cmp = s_tag(0x10, cmp + '\x00')
    #   key = s_tag(0x11, key + '\x00')
    #   val = s_tag(0x12, pack('<i', val))
    #   data = s_tag(0x81, cmp + key + val)
    #   L7 = layer7(6, 2, sess_id, data)
    #   return L7

    """ 
    CmpPLCShell actions 
    """

    def plcshell(self, command, command_args=None):
        if self.verbose:
            print("[*] " + command)
        if not self.sess_id:
            exit("[-] Login to Device first")
        tag1 = "\x11\x84\x80\x00" + pack("<I", self.sess_id)
        tag2 = "\x13\x84\x80\x00\x00\x00\x00\x00"
        data = tag1 + tag2 + s_tag(0x10, command + "\x00\x00\x00")
        if command_args:
            data += s_tag(0x12, command_args + "\x00\x00\x00")
        mL7 = layer7(0x11, 0x1, self.sess_id, data)
        self.send_layer7(mL7)
        tags = self.recv_layer7()

        if 0x82 not in tags:
            print("[-] plcshell: No tag 0x82 in response")
            self.disconnect()
            # sys.exit(1)
        return tags

    def start(self):
        res = self.plcshell("startprg")
        if "[OK]" in res:
            return True
        else:
            print("[-] startprg got *failed*: " + str(res))
            return False

    def stop(self):
        return self.plcshell("stopprg")

    def applist(self):
        return self.plcshell("applist")

    def status(self, app_name):
        res = self.plcshell("getprgstat")[0x82]

        if not app_name in res:
            self.l.error("No appname in status response!")
            return None

        # Parse status string
        s = res.split("Status:")[1].strip()
        retrieved_state = s[s.find("[") + 1 : s.find("]")]

        return retrieved_state

    def channelinfo(self):
        print("[*] ChannelInfo")
        deeper_tags = parse_tags_to_dict(self.plcshell("channelinfo")[0x82])
        print("[*] ChannelInfo retrieved")
        result = deeper_tags[0x20].rstrip("\x00")
        print("-" * 50)
        print(result)
        print("-" * 50)
        return result

    def memdump(self, addr, len=256):
        print("[*] Memdump")
        res_dump = ""
        # print('-' * 64)
        times = len / 64
        for i in range(0, times):
            cmd_args = "16#%0.2X %d" % (addr, 64)
            res_tags = self.plcshell("mem", cmd_args)[0x82]
            res_dump += parse_tags_to_dict(res_tags)[0x20]
            addr += 96

        print(res_dump)
        # print('-' * 64)
        return res_dump

    """    Reset warm: All variables are reset, except RETAIN and PERSISTENT variables.    """

    def reset(self):
        self.plcshell("resetprg")

    """    Reset cold: All variables are reset, except PERSISTENT variables.    """

    def reset_c(self):
        self.plcshell("resetprgcold")

    """ 
    CmpApp actions
    """

    """ Get App list (before login) """

    def readAppList(self):
        if not self.sess_id:
            print("[-] Login to Device first")
            return ""
        print("\n[c] Reading list of Applications")
        tagdata = s_tag(0x01, "\x00\x00\x00\x00\x00\xff\xff\xff\x7f")
        self.send_layer7(
            layer7(
                service_group=0x02, command_id=0x18, sess_id=self.sess_id, data=tagdata
            )
        )
        tags = self.recv_layer7()
        if 0x81 not in tags:
            print("No tag 0x81 in response")
            self.s.close()
            sys.exit(1)

        # See inside 0x81 recursively
        deeper_tags = parse_tags_to_dict(tags[0x81])
        # print('[*] Deeper response tags: ' + pretty_format_tagsdict(deeper_tags))

        if not 0x3 in deeper_tags:
            print("[-] Runtime has no applications loaded")
            self.s.close()
            sys.exit(1)

        appname = deeper_tags[3].rstrip("\x00")
        print("[*] Retrieved application names: " + appname)
        return appname

    """ Get area address """

    def getAreaAddress(self, area_index=0):
        if self.verbose:
            print("\n[c] Getting area address")
        if not self.app_sess_id:
            exit("[-] Login to App first")
        tagdata = s_tag(0x11, pack("<I", self.app_sess_id)) + s_tag(
            0x13, pack("<I", area_index)
        )
        self.send_layer7(
            layer7(
                service_group=0x02, command_id=0x38, sess_id=self.sess_id, data=tagdata
            )
        )
        tags = self.recv_layer7()
        if 0x14 not in tags:
            print("[-] No tag 0x14 in response")
            self.s.close()
            sys.exit(1)

        if len(tags[0x14]) == 4:
            area_addr = unpack("<I", tags[0x14])[0]
        elif len(tags[0x14]) == 8:
            area_addr = unpack("<II", tags[0x14])[0]
        else:
            print("[-] Retrieved invalid area address length!")
            self.s.close()
            sys.exit(1)

        if self.verbose:
            print("[*] Got area address %s" % hex(area_addr))
        return area_addr

    """ Read full status info"""

    def readAppStatus(self):
        if self.verbose:
            print("\n[c] Checking app status")
        if not self.app_sess_id:
            print("[-] readAppStatus: Login to App first")
            return None
        tagdata = s_tag(
            0x81,
            s_tag(0x11, pack("<I", self.app_sess_id))
            + s_tag(0x18, "\x01\x00\x01\x00")
            + s_tag(0x19, "\x01\x00"),
        )
        self.send_layer7(
            layer7(
                service_group=0x02, command_id=0x14, sess_id=self.sess_id, data=tagdata
            )
        )
        tags = self.recv_layer7()

        if tags == []:
            return None

        if 0x82 not in tags:
            print("[-] No readStatus result in response")
            self.s.close()
            return None

        device_operation_mode = tags[0x32]
        deeper_tags = parse_tags_to_dict(tags[0x82])
        sinfo = deeper_tags[0x13]

        rescode = unpack("<H", sinfo[0:2])[0]

        appstate_code = unpack("<I", sinfo[2:6])[0]

        if appstate_code == 1:
            appstate = "Run"
        elif appstate_code == 2:
            appstate = "Stop"
        elif appstate_code == 3:
            appstate = "Debug Breakpoint"
        elif appstate_code == 4:
            appstate = "Debug Step"
        elif appstate_code == 5:
            appstate = "Single Cycle"
        else:
            appstate = "Unknown"

        """
        Opstate
         NONE UINT32_C(0x00000000)
         PROGRAM_LOADED UINT32_C(0x00000001)
         DOWNLOAD UINT32_C(0x00000002)
         ONLINE_CHANGE UINT32_C(0x00000004)
         STORE_BOOTPROJECT UINT32_C(0x00000008)
         FORCE_ACTIVE UINT32_C(0x00000010)
         EXCEPTION UINT32_C(0x00000020)
         RUN_AFTER_DOWNLOAD UINT32_C(0x00000040)
         STORE_BOOTPROJECT_ONLY UINT32_C(0x00000080)
         EXIT UINT32_C(0x00000100)
         DELETE UINT32_C(0x00000200)
         RESET UINT32_C(0x00000400)
         RETAIN_MISMATCH UINT32_C(0x00000800)
         BOOTPROJECT_VALID UINT32_C(0x00001000)
         LOAD_BOOTPROJECT UINT32_C(0x00002000)
         FLOW_ACTIVE UINT32_C(0x00004000)
         RESET_OUTPUTS UINT32_C(0x00010000)
         COREDUMP_LOADED UINT32_C(0x00020000)
         EXECUTIONPOINTS_ACTIVE UINT32_C(0x00040000)
         COREDUMP_CREATING UINT32_C(0x00080000)
         SINGLE_CYCLE_ACTIVE UINT32_C(0x00100000)
         DISABLE_RESET UINT32_C(0x00200000)
        """
        opstate_code = unpack("<I", sinfo[6:10])[0]
        if opstate_code == 0x1001:
            opstate = "Normal"
        elif opstate_code == 0x1021:
            opstate = "Exception"
        elif opstate_code == 0x101001:
            opstate = "In_Single_Cycle"
        else:
            opstate = "Unknown"

        # import ipdb;ipdb.set_trace()
        lastchange = None
        exec_pos = None
        instance_pos = None
        if 0x1B in deeper_tags:
            lastchange = deeper_tags[0x1B]
        if 0x14 in deeper_tags:
            exec_pos = deeper_tags[0x14]
        if 0x16 in deeper_tags:
            instance_pos = deeper_tags[0x16]

        if self.verbose:
            print(
                "[*] Got AppStatus: Rescode %d State %s (%d) OpState %s (%s)"
                % (rescode, appstate, appstate_code, opstate, hex(opstate_code))
            )
        return (appstate, opstate, exec_pos)

    """ Login to App """

    def loginToApp(self, appname=None):

        if not appname:
            appname = self.readAppList()

        print("\n[c] Login to App " + appname)

        """
        [0x1] 53696d706c6556617241707000000000
        """

        tagdata_login = s_tag(0x1, appname)

        self.send_layer7(
            layer7(
                service_group=0x02,
                command_id=0x01,
                sess_id=self.sess_id,
                data=tagdata_login,
            )
        )
        tags = self.recv_layer7()

        if 0x81 not in tags:
            print("no tag 0x81 in response")
            self.s.close()
            sys.exit(1)

        # See inside 0x81 recursively
        deeper_tags = parse_tags_to_dict(tags[0x81])
        # print('[*] Deeper response tags: ' + pretty_format_tagsdict(deeper_tags))

        if 0x10 not in deeper_tags:
            print("no tag 0x10 in deeper_tags")
            self.s.close()
            sys.exit(1)

        if deeper_tags[0x10] == "\x18\x00":
            print("[-] The tag 0x10 is 1800. Already logged in error")
            self.s.close()
            self.reconnect()

        appSessId = deeper_tags[0x10][2:6]
        appSessId2 = deeper_tags[0x10][22:26]

        self.app_sess_id = unpack("<I", appSessId)[0]
        self.app_sess_id2 = unpack("<I", appSessId2)[0]
        self.appname = appname
        print(
            "[*] Login to App completed. Got AppSessId: 0x%s and AppSessId2: 0x%s"
            % (appSessId.encode("hex"), appSessId2.encode("hex"))
        )

    """ Single Cycle """

    def runSingleCycle(self):
        if self.verbose:
            print("\n[c] Executing Single Cycle")
        if not self.app_sess_id:
            print("[-] Single Cycle: Login to App first")
            return -1
        tagdata = s_tag(0x81, s_tag(0x11, pack("<I", self.app_sess_id)))
        self.send_layer7(
            layer7(
                service_group=0x02, command_id=0x22, sess_id=self.sess_id, data=tagdata
            )
        )
        tags = self.recv_layer7()
        if 0x01 not in tags:
            print("[-] Single Cycle: No tag 0x01 in response")
            return -1

        if tags[0x01] == "\x00\x00":
            if self.verbose:
                print("[*] Executed Single Cycle successfully")
            return 1
        elif tags[0x01] == "\x37\x00":
            print(
                "[*] Single Cycle failed (%s). App in Exception?"
                % tags[0x01].encode("hex")
            )
            return 0
        else:
            print(
                "[*] Single Cycle failed (%s). Other error" % tags[0x01].encode("hex")
            )
            return -1

    """ Logout from Device """

    def logoutFromDevice(self):
        if not self.s.sock:
            return
        print("\n[c] Logout from Device")
        if not self.sess_id:
            return
        tagdata = s_tag(0x1, struct.pack("<I", self.sess_id))
        self.send_layer7(
            layer7(
                service_group=0x01, command_id=0x03, sess_id=self.sess_id, data=tagdata
            )
        )
        tags = self.recv_layer7()
        if 0x0 in tags:
            print("[*] Logged out from Device")
            self.sess_id = None
        else:
            print("[-] Cannot log out from Device")

    """ Logout from App """

    def logoutFromApp(self):
        if not self.s.sock:
            return
        print("\n[c] Logout from App")
        if not self.app_sess_id:
            print("[-] No app_sess_id")

        tagdata = s_tag(0x0, pack("<I", self.app_sess_id))

        self.send_layer7(
            layer7(
                service_group=0x02, command_id=0x02, sess_id=self.sess_id, data=tagdata
            )
        )
        tags = self.recv_layer7()
        if 0x0 in tags:
            print("[*] Logged out from App")
            self.app_sess_id = None
            self.app_sess_id2 = None
        else:
            print("[-] Cannot log out from App")

    """ 
    CmpMonitor2 actions
    """

    """    Read Variables    """
    """
    TYPE   [0x2] size     [0x3] type     [0x4]bsize [0x5] bytecode
    INT     [0x2] 02000000 [0x3] 07000000 [0x4] 0500 [0x5] 02 24 39 06 00000000
    BYTE    [0x2] 01000000 [0x3] 02000000 [0x4] 0500 [0x5] 02 26 39 06 00000000
    WORD    [0x2] 02000000 [0x3] 03000000 [0x4] 0500 [0x5] 02 24 39 06 00000000 
    BOOL    [0x2] 01000000 [0x3] 00000000 [0x4] 0500 [0x5] 02 26 39 06 00000000
    UDINT   [0x2] 04000000 [0x3] 0c000000 [0x4] 0500 [0x5] 02 2c 56 06 00000000

    write_baba4 
    [0x1] id   [0x2] size     [0x3] type     [0x4]bsize [0x5] bytecode
    [0x1] 0100 [0x2] 04000000 [0x3] 04000000 [0x4] 0500 [0x5] 02 ac 39 06 00000000 
    [0x1] 0200 [0x2] 04000000 [0x3] 04000000 [0x4] 0500 [0x5] 02 c4 39 06 00000000 
    [0x1] 0300 [0x2] 02000000 [0x3] 03000000 [0x4] 0500 [0x5] 02 cc 3a 06 00000000
    [0x1] 0400 [0x2] 04000000 [0x3] 04000000 [0x4] 0500 [0x5] 02 c4 39 06 00000000

    """

    def read_variables(self, varlist):
        retrieved_list = []
        if self.verbose:
            print("[c] Reading variables")
        if not self.app_sess_id:
            exit("[-] Login to App first")

        # Auth tokens
        tag_1 = s_tag(
            0x1,
            pack("<I", self.app_sess_id)
            + pack("<I", self.app_sess_id2)
            + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )

        # Iterate through varlist
        t82_multiple = ""
        for num, v in enumerate(varlist):
            read_id = 50 + num  # 32,33..
            read_size = v.size
            read_type = v.type

            if v.offset > 65535:
                print("read_variables: variable offset is too big!")
                continue

            bcode = "\x02" + struct.pack("<H", v.offset) + "\x06\x00"
            read_bcode = bcode + "\x00\x00\x00"
            read_bsize = len(bcode)

            t82_one = s_tag(
                0x82,
                s_tag(0x1, pack("<I", read_id))
                + s_tag(0x2, pack("<I", read_size))
                + s_tag(0x3, pack("<I", read_type))
                + s_tag(0x4, pack("<I", read_bsize))
                + s_tag(0x5, read_bcode),
            )
            t82_multiple += t82_one

        # List of vars to read. IDE sends s_tag(0x81, t82_1+t82_2+t82_3+t82_4)
        tag_81 = s_tag(0x81, t82_multiple)
        tagdata = tag_1 + tag_81
        if self.verbose:
            print(
                "[*] Reading bsize %s bcode %s" % (read_bsize, read_bcode.encode("hex"))
            )

        self.send_layer7(
            layer7(
                service_group=0x1B, command_id=0x1, sess_id=self.sess_id, data=tagdata
            )
        )
        res_tags = self.recv_layer7()

        """
        Response
               id   size
        [0x40] 0100 04000000 | f7000 000 
             | 0200 04000000 | f1000 000 
             | 0300 02000000 | 0124 
             | 0400 04000000 | babababa 0000
        """
        # 0x40 is ReadValueList. 0x41 is error
        if not 0x40 in res_tags:
            print("[-] Error when reading variables")
            return None

        if res_tags[0x40] == "\x04\x80\x0a\x00\x00\x00\x00\x00":
            print("[-] Error when reading variables")
            return None

        if res_tags[0x40] == "\x64\x00\x02\x00\x00\x00\x00\x00":
            print("[-] Error when reading variables")
            return None

        # Check IDs
        for num, v in enumerate(varlist):
            expected_id = 50 + num  # 32,33..
            str_expected_id = str(hex(expected_id)[2:])
            if not (str_expected_id.decode("hex") in res_tags[0x40]):
                print(
                    "[-] This variable is not retrieved: 0x"
                    + str(expected_id)
                    + " ("
                    + str_expected_id
                    + ")"
                )

        # Parse results
        retrieved_list = [res_tags[0x40].encode("hex")]

        if self.verbose:
            print("[*] Variables retrieved: " + str(retrieved_list))
        return retrieved_list

        # result_id = unpack("<H", tags[0x40][0:2])[0]
        # result_size= unpack("<I", tags[0x40][2:6])[0]
        # result_val = tags[0x40][5:]

        # if result_val == '\x00\x10\x02\x00\x00\x00\x00':
        #     print('[*] Variable %d does not exist' % result_id)
        # else:
        #     self.iec_variables[result_id] = (result_size, result_val)
        #     print('[*] Variable %d of size %d == %s' % (result_id, result_size, result_val.encode('hex')))

        # return

    """    Write Variables    """
    """

                    |0  |size |0   |value                                         | ?            | bcode          | ?
    [0x1] ... [0x3] 0000 0400 0000 babababa                                       | 1b00150c00   | 02 a8 58 0600     | 170c0904 1b 06000 10000 17040904 17080904 0400                   
    [0x1] ... [0x3] 0000 0f00 0000 | 4b 4f 4b 4f 4b 4f 4b 4f 4b 4f 4b 4f 4b 4f 00 | 1b00150c00   | 02 d0 4d 06 00    | 170c0904 1b 06000 10000 17040904 17080904 0400 00             #<--string.pcapng 

                    |0  |size |0   |value                                           | ?        | bcode          | ?        | ?
    [0x1] ... [0x3] 0000 0700 0000 | 43 41 54 44 4f 47 00 |                         1b00150c00 | 02 24 4e 06 00 | 170c0904 | 1b 06 00 01 00 00 17 04 09 04 17 08 09 04 04 00 00  #<--string_catdog.pcapng 

    

    """

    def write_variables(self, varlist, values, is_raw_bytestr=False):
        if self.verbose:
            print("[c] Writing variables")

        if not self.app_sess_id:
            exit("Login to App first")

        # Auth tokens
        tag_1 = s_tag(
            0x1,
            pack("<I", self.app_sess_id)
            + pack("<I", self.app_sess_id2)
            + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )

        # Iterate through varlist
        t3_multiple = ""
        for num, v in enumerate(varlist):
            write_value = values[num]

            if is_raw_bytestr:
                packed_write_value = write_value
            else:
                # TODO: compare type,pack
                exit("not implemented")

            # write_bcode = bcode + "\x00\x00\x00"
            # write_bsize = len(bcode)

            bcode = "\x02" + struct.pack("<H", v.offset) + "\x06\x00"

            # Magic sequences (IDE x32 3.5 SP16, Runtime: sutd 32):
            # unknown_1 = "\x1b\x00\x15\x0c"
            # unknown_2 = "\x17\x0c\x09\x04" + "\x1b\x06\x00\x01"
            # unknown_3 = "\x17\x04\x09\x04" + "\x17\x08\x09\x04" + "\x04\x00"

            # Magic sequences (IDE 3.5 SP17 Patch 1 x64, Runtime: Linux SL 64 4.0.0.0 Target 4102):
            unknown_1 = "\x1b\x00\x15\x10"
            unknown_2 = "\x17\x10\x09\x04" + "\x1b\x06\x00\x01"
            unknown_3 = "\x17\x08\x09\x08" + "\x17\x0c\x09\x04" + "\x04\x00"

            tag_3 = s_tag(
                0x3,
                "\x00\x00"
                + pack("<H", v.size)
                + "\x00\x00"
                + write_value
                + unknown_1
                + "\x00"
                + bcode
                + unknown_2
                + "\x00\x00"
                + unknown_3
                + "\x00\x00",
            )

            t3_multiple += tag_3

        # Auth and varlist
        tagdata = tag_1 + t3_multiple
        self.send_layer7(
            layer7(
                service_group=0x1B, command_id=0x2, sess_id=self.sess_id, data=tagdata
            )
        )

        # Response
        res = self.recv_layer7()

        #  0x41 is error
        if 0x41 in res:
            err_code = struct.unpack("<I", res[0x41])[0]
            if err_code == 0x05:
                print("[-] Error when writing variables: Invalid pointer")
            elif err_code == 0x08:
                print("[-] Error when writing variables: Buffer size exceeded")
            elif err_code == 0x0C:
                print("[-] Error when writing variables: Mon exception")
            else:
                print("[-] Error when writing variables: " + hex(err_code))
            return False

        elif res == {}:
            if self.verbose:
                print("[*] Variables written")
            return True
        else:
            if self.verbose:
                print(
                    "[-] Error when writing variables: response should be empty "
                    + str(res)
                )
            return False
        return False

    """ CmpFuzz actions """

    # [0xff7f] 0203 no such cmd?
    # [0xff7f] 0103 no such service?
    def ping_cmpfuzz(self):
        if self.verbose:
            print("\n[c] Pinging CmpFuzz")
        if not self.app_sess_id:
            exit("[-] Login to App first")
        tagdata = s_tag(0x01, "\x00\x00")
        self.send_layer7(
            layer7(
                service_group=0x0100,
                command_id=0x13,
                sess_id=self.sess_id,
                data=tagdata,
            )
        )
        tags = self.recv_layer7()
        print(tags)
        return
