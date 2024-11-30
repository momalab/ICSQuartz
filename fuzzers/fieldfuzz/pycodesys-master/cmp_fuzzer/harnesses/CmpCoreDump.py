SERVICE_ID = 0x1f

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
