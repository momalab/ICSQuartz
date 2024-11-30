#! /usr/bin/env python2
from lib import pycodesys
import time

'''
Codesys Shell client implementation
'''

cds = pycodesys.CodesysNode(host='softplc', port=11740, verbose=False)
chan_id = cds.connect()
if not chan_id:
    exit(0)

cds.loginToDevice()

#cds.loginToApp()
addr = 0xFFF

while True:
    addr -= 1024
    cds.memdump(addr)

# hostname = cds.host + ' plc'
#
# try:
#     while True:
#         print('--Codesys3 shell--')
#         incmd = str(raw_input(hostname + ' > '))
#         # cds.plcshell(incmd)
#         exit(1)
#
# except KeyboardInterrupt:
#     print('Interrupted')
#     cds.disconnect()
#     exit(0)
#

