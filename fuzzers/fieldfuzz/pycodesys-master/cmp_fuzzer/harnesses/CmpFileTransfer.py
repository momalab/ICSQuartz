from lib.layers import s_tag


class CmpFileTransfer:
    SERVICE_ID = 0x08
    SERVICE_HANDLER_ADDRESS = 0x55555D7E5B00

    def get_fileinfo(self, inj):
        command_id = 0x01
        tag01 = s_tag(0x01, inj)
        tag10 = s_tag(0x10,"\x02\x00\x00\x00")
        l7_data = tag01 + tag10
        return l7_data, command_id


    def start_download(self):
        command_id = 0x02
        raise NotImplementedError()


    def restart_download(self):
        command_id = 0x03
        raise NotImplementedError()


    def download(self):
        command_id = 0x04
        raise NotImplementedError()


    def start_upload(self, inj):
        command_id = 0x05
        # "\x50\x6c\x63\x4c\x6f\x67\x5f\x32\x2e\x63\x73\x76\x00\x00\x00\x00"
        tag_1 = s_tag(0x01, inj)
        tag_2 = s_tag(0x02,"\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        l7_data = tag_1 + tag_2
        return l7_data, command_id


    def restart_upload(self):
        command_id = 0x06
        raise NotImplementedError()


    def upload(self, inj):
        command_id = 0x07
        # "\x03\x00\x00\x00\x00\x00\x00\x00"
        tag_5 = s_tag(0x05, inj)
        l7_data = tag_5
        return l7_data, command_id


    def end(self, inj):
        command_id = 0x08
        # "\x03\x00\x00\x00\x50\x6c\x63\x4c\x6f\x67\x5f\x32" \
        #                 "\x2e\x63\x73\x76\x00\x00\x00\x00"
        tag_7 = s_tag(0x07, "\x03\x00\x00\x00"+inj+"\x00\x00\x00\x00")
        tag_2 = s_tag(0x02,"\x01\x00\x00\x00" \
                "\x26\xa1\x07\x00\x00\x00\x00\x00")
        l7_data = tag_7 + tag_2
        return l7_data, command_id


    def get_dir_info(self, inj):
        command_id = 0x0c
        tag0b = s_tag(0x0b, inj)
        l7_data = tag0b
        return l7_data, command_id

    def delete_file(self, inj):
        command_id = 0x0e
        tag_1 = s_tag(0x01, inj)
        l7_data = tag_1
        return l7_data, command_id


    def create_dir(self, inj):
        command_id = 0x10
        tag_0b = s_tag(0x0b, inj)
        l7_data = tag_0b
        return l7_data, command_id


    def delete_dir(self, inj):
        command_id = 0x11
        tag_0b = s_tag(0x0b, inj)
        l7_data = tag_0b
        return l7_data, command_id
