#! /usr/bin/env python2
from lib import pycodesys
from lib.layers import s_tag
from time import sleep





'''
Keep channel alive
'''

cds = pycodesys.CodesysNode(host='softplc', port=11740, verbose=True)
chan_id = cds.connect()

while True:
    cds.reconnect()


# while True:
#     cds.recv_layer7_2()


# Login to Device
#cds.loginToDevice()

# while True:
#     sleep(1)
#     #cds.recv_layer7()
#     cds.send_keepalive()

#cds.recv_layer7()

#sleep(5)

# print('--1')
# cds.readAppList()
# sleep(1)
# print('--2')
# cds.readAppList()
# print('--3')
# cds.readAppList()



# List loaded applications
#appname = cds.readAppList()
#print(appname)

#cds.loginToApp(appname)


#cds.disconnect()









