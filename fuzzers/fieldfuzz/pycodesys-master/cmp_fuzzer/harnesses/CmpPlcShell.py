SERVICE_ID = 0x11


def plcshell(self, command, command_args=None):
    if self.verbose:
        print('[*] ' + command)
    if not self.sess_id:
        exit('[-] Login to Device first')
    tag1 = "\x11\x84\x80\x00" + pack("<I", self.sess_id)
    tag2 = "\x13\x84\x80\x00\x00\x00\x00\x00"
    data = tag1 + tag2 + s_tag(0x10, command + '\x00\x00\x00')
    if command_args:
        data += s_tag(0x12, command_args + '\x00\x00\x00')
    mL7 = layer7(0x11, 0x1, self.sess_id, data)
    self.send_layer7(mL7)
    tags = self.recv_layer7()

    if 0x82 not in tags:
        print('[-] plcshell: No tag 0x82 in response')
        self.disconnect()
        # sys.exit(1)
    return tags
