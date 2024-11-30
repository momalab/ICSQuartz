#! /usr/bin/env python2

import sys
sys.path.insert(0, "..")
from opcua import Client, ua

'''
Feeder for OPCUA
'''


'''
    Symbolic Variable: PLC_PRG.beef01
    Path: "0: Root, 0: Objects, 2: DeviceSet, 4: CODESYS    Control    Win   V3, 3: Resources, 4: SimpleVarApp, 3: Programs, 4: PLC_PRG, 4: beef01"
    NodeId: "ns = 4; s = | var | CODESYSW Control Win V3.SimpleVarApp.PLC_PRG.beef01"
    Relative: root.get_children()[0].get_children()[1].get_variables()[0].get_value()
'''

if __name__ == "__main__":

    PLC_HOST='192.168.120.131'


    client = Client("opc.tcp://"+PLC_HOST+":4840/")


    def read_vars(variables):
        for var in variables:
            name = var.get_browse_name().Name
            type = var.get_data_type_as_variant_type()
            value = var.get_value()
            print(name,type.name,value)




    def write_vars(variables):
        for var in variables:

            name = var.get_browse_name().Name
            type = var.get_data_type_as_variant_type()
            value = var.get_value()

            print('writing ' + name)

            if name not in ['mStr', 'mResult']:
                var.set_value(23, type)

    try:
        client.connect()
        root = client.get_root_node()

        # Find device node
        device_node = root.get_child(["0:Objects", "2:DeviceSet"]).get_children()[0]
        print("Found device: ", device_node)

        application_node=device_node.get_child(["3:Resources"]).get_children()[0]
        print("Found application: ", application_node)

        variables=application_node.get_child(["3:Programs", "4:PLC_PRG"]).get_children()
        print("Read Variables: ")
        read_vars(variables)
        print("Write Variables: ")
        write_vars(variables)
        print("Read Variables: ")
        read_vars(variables)



        # Now getting a variable node using its browse path
        # myvar = root.get_child(["0:Objects", "2:MyObject", "2:MyVariable"])
        # obj = root.get_child(["0:Objects", "2:MyObject"])
        # print("myvar is: ", myvar)
        # print("myobj is: ", obj)


        # get a specific node knowing its node id
        #var = client.get_node(ua.NodeId(1002, 2))
        #var = client.get_node("ns=3;i=2002")
        #print(var)
        #var.get_data_value() # get value of node as a DataValue object
        #var.get_value() # get value of node as a python builtin
        #var.set_value(ua.Variant([23], ua.VariantType.Int64)) #set node value using explicit data type
        #var.set_value(3.9) # set node value using implicit data type



        # Stacked myvar access
        # print("myvar is: ", root.get_children()[0].get_children()[1].get_variables()[0].get_value())

    finally:
        client.disconnect()
