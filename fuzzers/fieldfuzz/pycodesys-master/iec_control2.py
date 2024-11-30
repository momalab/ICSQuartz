#! /usr/bin/env python2
from lib import pycodesys

'''
Control the Codesys IEC application
Start / Stop
Warm and Cold reset
'''

cds = pycodesys.CodesysNode(host='softplc', port=11740, verbose=True)
chan_id = cds.connect()

# Login to Device

cds.loginToDevice()

# List loaded applications
appname = cds.readAppList()
print(appname)

cds.loginToApp(appname)

# Get application status
#appstatus = cds.status(appname)
#print(appstatus)


#cds.readAppStatus()
#cds.reset()

# Start application
#cds.start()

#cds.stop()
#cds.runSingleCycle()

#cds.stop()

#cds.reset()

# Cold-reset variables
#cds.reset_c()

# Get application status
#appstatus = cds.status(appname)
#print(appstatus)

#cds.ping_cmpfuzz()



cds.disconnect()









