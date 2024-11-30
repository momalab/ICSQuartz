SERVICE_ID = 0x02

''' 
    CmpApp actions
    '''

''' Get App list (before login) '''


def readAppList(self):
    if not self.sess_id:
        print('[-] Login to Device first')
        return ''
    print("\n[c] Reading list of Applications")
    tagdata = s_tag(0x01, "\x00\x00\x00\x00\x00\xff\xff\xff\x7f")
    self.send_layer7(layer7(service_group=0x02, command_id=0x18, sess_id=self.sess_id, data=tagdata))
    tags = self.recv_layer7()
    if 0x81 not in tags:
        print('No tag 0x81 in response')
        self.s.close()
        sys.exit(1)

    # See inside 0x81 recursively
    deeper_tags = parse_tags_to_dict(tags[0x81])
    # print('[*] Deeper response tags: ' + pretty_format_tagsdict(deeper_tags))

    if not 0x3 in deeper_tags:
        print('[-] Runtime has no applications loaded')
        self.s.close()
        sys.exit(1)

    appname = deeper_tags[3].rstrip('\x00')
    print('[*] Retrieved application names: ' + appname)
    return appname


''' Get area address '''


def getAreaAddress(self, area_index=0):
    if self.verbose:
        print("\n[c] Getting area address")
    if not self.app_sess_id:
        exit('[-] Login to App first')
    tagdata = s_tag(0x11, pack("<I", self.app_sess_id)) + s_tag(0x13, pack("<I", area_index))
    self.send_layer7(layer7(service_group=0x02, command_id=0x38, sess_id=self.sess_id, data=tagdata))
    tags = self.recv_layer7()
    if 0x14 not in tags:
        print('[-] No tag 0x14 in response')
        self.s.close()
        sys.exit(1)

    if len(tags[0x14]) == 4:
        area_addr = unpack('<I', tags[0x14])[0]
    elif len(tags[0x14]) == 8:
        area_addr = unpack('<II', tags[0x14])[0]
    else:
        print('[-] Retrieved invalid area address length!')
        self.s.close()
        sys.exit(1)

    if self.verbose:
        print('[*] Got area address %s' % hex(area_addr))
    return area_addr


''' Read full status info'''


def readAppStatus(self):
    if self.verbose:
        print("\n[c] Checking app status")
    if not self.app_sess_id:
        print('[-] readAppStatus: Login to App first')
        return None
    tagdata = s_tag(0x81,
                    s_tag(0x11, pack("<I", self.app_sess_id)) \
                    + s_tag(0x18, "\x01\x00\x01\x00") \
                    + s_tag(0x19, "\x01\x00"))
    self.send_layer7(layer7(service_group=0x02, command_id=0x14, sess_id=self.sess_id, data=tagdata))
    tags = self.recv_layer7()

    if tags == []:
        return None

    if 0x82 not in tags:
        print('[-] No readStatus result in response')
        self.s.close()
        return None

    device_operation_mode = tags[0x32]
    deeper_tags = parse_tags_to_dict(tags[0x82])
    sinfo = deeper_tags[0x13]

    rescode = unpack('<H', sinfo[0:2])[0]

    appstate_code = unpack('<I', sinfo[2:6])[0]

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

    '''
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
    '''
    opstate_code = unpack('<I', sinfo[6:10])[0]
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
    if 0x1b in deeper_tags:
        lastchange = deeper_tags[0x1b]
    if 0x14 in deeper_tags:
        exec_pos = deeper_tags[0x14]
    if 0x16 in deeper_tags:
        instance_pos = deeper_tags[0x16]

    if self.verbose:
        print('[*] Got AppStatus: Rescode %d State %s (%d) OpState %s (%s)' % (
        rescode, appstate, appstate_code, opstate, hex(opstate_code)))
    return (appstate, opstate, exec_pos)


''' Login to App '''


def loginToApp(self, appname=None):
    if not appname:
        appname = self.readAppList()

    print("\n[c] Login to App " + appname)

    '''
    [0x1] 53696d706c6556617241707000000000
    '''

    tagdata_login = s_tag(0x1, appname)

    self.send_layer7(layer7(service_group=0x02, command_id=0x01, sess_id=self.sess_id, data=tagdata_login))
    tags = self.recv_layer7()

    if 0x81 not in tags:
        print('no tag 0x81 in response')
        self.s.close()
        sys.exit(1)

    # See inside 0x81 recursively
    deeper_tags = parse_tags_to_dict(tags[0x81])
    # print('[*] Deeper response tags: ' + pretty_format_tagsdict(deeper_tags))

    if 0x10 not in deeper_tags:
        print('no tag 0x10 in deeper_tags')
        self.s.close()
        sys.exit(1)

    if deeper_tags[0x10] == "\x18\x00":
        print('[-] The tag 0x10 is 1800. Already logged in error')
        self.s.close()
        self.reconnect()

    appSessId = deeper_tags[0x10][2:6]
    appSessId2 = deeper_tags[0x10][22:26]

    self.app_sess_id = unpack('<I', appSessId)[0]
    self.app_sess_id2 = unpack('<I', appSessId2)[0]
    self.appname = appname
    print('[*] Login to App completed. Got AppSessId: 0x%s and AppSessId2: 0x%s' % (
        appSessId.encode('hex'), appSessId2.encode('hex')))


''' Single Cycle '''


def runSingleCycle(self):
    if self.verbose:
        print("\n[c] Executing Single Cycle")
    if not self.app_sess_id:
        print('[-] Single Cycle: Login to App first')
        return -1
    tagdata = s_tag(0x81, s_tag(0x11, pack("<I", self.app_sess_id)))
    self.send_layer7(layer7(service_group=0x02, command_id=0x22, sess_id=self.sess_id, data=tagdata))
    tags = self.recv_layer7()
    if 0x01 not in tags:
        print('[-] Single Cycle: No tag 0x01 in response')
        return -1

    if tags[0x01] == "\x00\x00":
        if self.verbose:
            print('[*] Executed Single Cycle successfully')
        return 1
    elif tags[0x01] == "\x37\x00":
        print('[*] Single Cycle failed (%s). App in Exception?' % tags[0x01].encode('hex'))
        return 0
    else:
        print('[*] Single Cycle failed (%s). Other error' % tags[0x01].encode('hex'))
        return -1
