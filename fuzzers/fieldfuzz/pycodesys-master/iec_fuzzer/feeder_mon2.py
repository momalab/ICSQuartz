#! /usr/bin/env python2
from lib import pycodesys
import pickle, os, struct, time

'''
Feeder for TCP CmpMon2
'''


class Mon2Feeder:
    cds = None

    def __init__(self, cds=cds):
        self.cds=cds


    def read_vars(self, varlist):
        try:

            cds.read_variables(varlist)
        except Exception as e:
            print(e)
            cds.disconnect()
        finally:
            cds.disconnect()

    def write_vars(self, varlist):
        value = "jopa"
        len = 4
        cds.write_variables(size=len, value=value, bcode=bcode)


    def write_var(self, varlist):
        pass
