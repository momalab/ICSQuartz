SERVICE_GRP = 0x01

def getTargetident(self):
    # TODO
    print("[c] getTargetident")
    if self.verbose:
        context.log_level = 'debug'
    if not self.s:
        self.s = remote(self.host, self.port, typ='tcp')
    # mL7 = "\x55\xcd\x10\x00\x01\x00\x01\x00\x60\x2b\x99\x8b\x10\x00\x00\x00" \
    #      "\x00\x00\x00\x00\x01\x8c\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    #      "\x00\x00\x00\x00"

    # tagdata = "\x01\x8c\x80\x00\x00\x10\x00\x00\x01\x00\x92\x17\x28\x10\x05\x03"

    tagdata = s_tag(0x1, "\x00\x10\x00\x00\x01\x00\x92\x17\x28\x10\x05\x03")

    self.send_layer7(layer7(service_group=SERVICE_GRP, command_id=0x01, sess_id=0x0, data=tagdata))
    self.recv_layer7()

    return False


'''    CmpDevice ResetOriginDevice    '''
def resetOriginDevice(self):
    # TODO
    print("[c] resetOriginDevice")
    if self.verbose:
        context.log_level = 'debug'
    if not self.s:
        self.s = remote(self.host, self.port, typ='tcp')

    tagdata = ""

    self.send_layer7(layer7(service_group=SERVICE_GRP, command_id=0x01, sess_id=0x0, data=tagdata))
    tags = self.recv_layer7()

    if 0x84 not in tags:
        print('[-] s_tag 0x84 not found in response')
        return False

    data = tags[0x84]
    tags = parse_tags_to_dict(data)
    print(pretty_format_tagsdict(tags))
    return True

'''    CmpDevice loginToDevice    '''
def loginToDevice(self):
    #
    # Login to Device (Get a session with CmpDevice -> Login)
    #
    print('[c] Login to Device')
    tag_10 = s_tag(0x10, '\x00\x00')
    data = s_tag(0x22, pack('<H', 1)) + s_tag(0x81, tag_10)
    L7 = layer7(service_group=1, command_id=2, sess_id=0x11, data=data)
    self.send_layer7(L7)

    # st, res = recv_block_driver_tcp(self.s)

    # L4 = dissect_l4(res)
    # self.ack = unpack_from('<I', L4, 4)[0]
    # L7_body = dissect_l7_body(L4, 4)
    # tags = parse_tags_to_dict(L7_body)

    tags = self.recv_layer7()

    if 0x82 not in tags:
        print('s_tag 0x82 not found in response')
        self.sess_id = 0
        return False

    data = tags[0x82]
    tags = parse_tags_to_dict(data)

    if not all(k in tags for k in (0x20, 0x21)):
        print('s_tag 0x20 or 0x21 not found in response')
        self.s.close()
        sys.exit(1)

    status = tags[0x20]
    new_sess_id = tags[0x21]

    if len(status) != 2:
        print('Length of status s_tag is not 2 bytes')
        self.s.close()
        sys.exit(1)

    status = unpack('<H', status)[0]
    if status != 0:
        print('Response status not ERR_OK')
        self.s.close()
        sys.exit(1)

    if len(new_sess_id) != 4:
        print('Length of session id s_tag is not 4 bytes')
        self.s.close()
        sys.exit(1)

    print("[*] Got session id: " + new_sess_id.encode('hex'))
    new_sess_id = unpack('<I', new_sess_id)[0]

    print("[*] Logged in")
    self.sess_id = new_sess_id
    return True

