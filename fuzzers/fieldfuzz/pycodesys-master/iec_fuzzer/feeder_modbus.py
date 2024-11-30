#!/usr/bin/python2

from pymodbus.client.sync import ModbusTcpClient
from pymodbus.exceptions import ConnectionException
from pymodbus.register_read_message import ReadHoldingRegistersResponse

'''
Feeder for Modbus TCP
Holding registers are read/write 16bit (most common)
Input registers are read-only 16bit
Coils are read/write 1bit
Discrete inputs are read-only 1bit
'''

class ModbusFeeder:
    ip = ''
    port = 0
    slave_id=0
    num_registers=0
    c = None

    def __init__(self, ip='192.168.120.128', port=502, slave_id=0, num_registers=10):
        self.ip = ip
        self.port = port
        self.slave_id = slave_id
        self.num_registers = num_registers

    def read_regs(self):
        inputs=None
        discrete_inputs = None
        holds = None

        print('Reading registers...')
        #inputs = self.c.read_input_registers(1, self.num_registers)
        #discrete_inputs = self.c.read_discrete_inputs(1, self.num_registers)
        holds = self.c.read_holding_registers(0, self.num_registers)

        if (isinstance(holds, ReadHoldingRegistersResponse)):
            return holds
        else:
            print('Modbus - cannot read: ' + str(type(holds)))
            return None

    def write_reg(self, id, value):
        self.c.write_register(id, value)

    def write_regs(self, values_list):
        self.c.write_registers(0, values_list)


    def connect(self):
        try:
            self.c = ModbusTcpClient(self.ip)
            if self.c.connect():
                print('Modbus connected')
        except ConnectionException as e:
            print('Cannot connect to modbus slave')
        except Exception as e:
            print(str(type(e))+' '+str(e))

    def disconnect(self):
        self.c.close()

