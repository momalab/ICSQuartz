#! /usr/bin/env python2

import datetime, argparse
import json
import math
import os, sys, time, logging, traceback
import random
from random import choice
from time import sleep



sys.path.append("..")
from lib.pycodesys import CodesysNode, VMeta, CDS_WORD, CDS_INT, CDS_SIZE, CDS_TYPE_IDS
from lib.utils import pretty_format_tagsdict
from lib.layers import layer7

from feeders import CmpFeeder
from harnesses.CmpFileTransfer import CmpFileTransfer

'''
Fuzzer for IEC application variables
Keepalive interval = 1000 ms
'''


class CMPFuzzer:
    l = None
    cds = None
    iterCnt = 0
    appname = ''
    appstate = 'Checking'
    appstate2 = 'Checking'
    app_exec_pos = ''
    total_time = 0
    iteration_time = 0
    time_to_crash = 0
    application_crashes = 0
    # runtime_crashes=0
    previous_appstate = ''
    previous_appstate2 = ''
    # retrieved_values = None
    wrote_values = None
    app_is_crashed = False
    runtime_is_down = False
    iter_skipped = False
    valid_area0_start = 0
    prg_profile = {}
    STATS_SHOW_EVERY = 1
    THROTTLE_S = 0.05
    SHUTDOWN_DELAY = 2
    VERBOSE = False
    last_cmd_failed = False

    # LOG_F = 'log.txt'

    def __init__(self):
        # Init logger and stats
        self.l = logging.getLogger('fuzz_iec')
        lhandler = logging.StreamHandler()
        lhandler.setLevel(logging.DEBUG)
        self.l.addHandler(lhandler)

        self.l.debug('[*] CMPFuzzer initialized')

    def show_stats(self):
        T_GREEN = '\033[92m'
        T_YELLOW = '\33[33m'
        T_ENDC = '\033[0m'
        T_RED = '\033[91m'
        if not self.VERBOSE:
            os.system('clear')

        if self.appstate2 == 'Normal':
            statetext = T_GREEN + self.appstate + T_ENDC
            state2text = T_GREEN + self.appstate2 + T_ENDC
            state2text = T_GREEN + self.appstate2 + T_ENDC
        elif self.appstate2 == 'Exception':
            statetext = T_RED + self.appstate + T_ENDC
            state2text = T_RED + self.appstate2 + T_ENDC
        else:
            statetext = T_YELLOW + self.appstate + T_ENDC
            state2text = T_YELLOW + self.appstate2 + T_ENDC

        print('\n|-- --- ---')
        print("|-- Fuzzing ---")
        print (
            "|-- Iteration: #{}  :: Crashes: {} :: Status: [{}] [{}]".format(self.iterCnt, self.application_crashes,
                                                                             statetext, state2text))
        print('|-- Total time: %.3f s :: TTC: %.3f ms :: Iteration time: %.3f ms' % (
            self.total_time, self.time_to_crash * 1000, self.iteration_time * 1000))
        print("|-- Payload: %s" % self.wrote_values.encode('hex'))
        print('|-- --- ---')
        print('|-- App name: %s :: Chan: %02x :: Area: %s' % (
            self.appname, self.cds.chan_id, hex(self.valid_area0_start)))
        print('|-- Status change: %s %s --> %s %s' % (
            self.previous_appstate, self.previous_appstate2, self.appstate, self.appstate2))
        print('|-- Exception detected: %s :: Pos: %s' % (self.app_is_crashed, self.app_exec_pos))
        print('|-- Runtime down: %s :: Throttling: %.1f ms' % (self.runtime_is_down, self.THROTTLE_S * 1000))
        print('|-- --- ---\n')
        if self.app_is_crashed:
            print('\n\n ** APP CRASHED. Needs reset **\n\n')

        if self.runtime_is_down:
            print('\n\n ** RUNTIME IS DOWN. Needs restart **\n\n')

        if self.iter_skipped:
            print('\n\n ** ON HOLD **\n\n')

    def read_appstates(self):

        if self.cds.blk_failure:
            return None

        self.previous_appstate = self.appstate
        self.previous_appstate2 = self.appstate2

        self.appstate = 'Checking'
        self.appstate2 = 'Checking'

        st = self.cds.readAppStatus()
        if st:
            self.appstate, self.appstate2, self.app_exec_pos = st
            return self.appstate
        else:
            return None

    '''
    Checks
    '''

    # def runtime_healtcheck(self):
    #     if self.cds.blk_failure:
    #         self.runtime_is_down = True
    #     else:
    #         self.runtime_is_down = False
    #     return self.runtime_is_down

    '''
    Inputs
    '''

    def generate_inputs(self, varlist):
        res = []
        for var in varlist:
            res.append(os.urandom(CDS_SIZE[var.type]))
        return res

    def stringify_inputs(self, inputslist):
        res = []
        for num, var in enumerate(inputslist):
            res.append(str(num) + ' : ' + var.encode('hex'))
        return res

    '''
    Events
    '''

    def log_crash(self):

        print('[*] logging crash')

        # Log
        if not os.path.exists("results/"):
            os.makedirs("results/")
        with open("results/crashlog.txt", "a") as logfile:
            ts = time.time()
            st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            logfile.write(
                " %s Crash. Application: %s. Iteration: %d. To crash: %.3f ms. Iteration time: %.3f ms. Inputs: %s \n" % (
                    st, self.appname, self.iterCnt, self.time_to_crash * 1000, self.iteration_time * 1000,
                    self.wrote_values))


    '''
    Test Inputs
    '''

    def test_inputs(self):
        print('[*] Dry run: just testing the inputs')
        pass

    '''
    Run
    '''

    def run(self):
        # Create connection
        self.cds = CodesysNode(host='0.0.0.0', port=11740, verbose=self.VERBOSE)
        if not self.cds.connect():
            exit('[-] Cannot connect. Is runtime down?')

        self.cds.loginToDevice()

        # Find loaded application
        self.appname = self.cds.readAppList()
        if len(self.appname) > 3:
            self.l.debug('Found application: ' + self.appname)

        self.cds.loginToApp(self.appname)

        '''
        Main fuzz loop
        '''

        # Measure iteration time
        total_time_start = time.time()
        self.no_crash_since = total_time_start

        try:

            # Fuzz loop
            while True:
                if self.VERBOSE:
                    print('[*] --- Iteration %d ---' % self.iterCnt)

                # Read runtime state, reconnect
                if self.cds.blk_failure:
                    if self.VERBOSE:
                        print('reconnecting to runtime... %s', self.cds.blk_failure)
                    self.time_to_crash = time.time() - self.no_crash_since
                    self.iteration_time = time.time() - iteration_start
                    self.cds.reconnect()
                    # count runtime crash
                    self.log_crash()
                    self.application_crashes += 1
                    self.no_crash_since = time.time()

                    if not self.cds.loginToDevice():
                        # Fails sometimes on '\x01\x01\x88\xc9\x01\x00\x00\x00\x01\x00\x00\x00\x1c\x00\x00\x00\x87\xb87\x8cU\xcd\x10\x00\x81\x00\x02\x00\x11\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x03\x82\x80\x00\x01\x03'
                        # need to just skip the cycle
                        continue
                    # Find loaded application
                    self.appname = self.cds.readAppList()
                    if len(self.appname) > 3:
                        self.l.debug('Found application: ' + self.appname)
                    self.cds.loginToApp(self.appname)
                    # Skip this iteration
                    continue

                # Otherwise, if no failure

                # Read app state, reset
                if not self.cds.sess_id and not self.cds.loginToDevice():
                    continue

                if not self.cds.app_sess_id and not self.cds.loginToApp():
                    continue

                anss = self.read_appstates()
                if not anss:
                    # print ('Fuzzer: read_appstates failed')
                    self.last_cmd_failed = True
                    continue
                if self.appstate2 == 'Exception':
                    self.app_is_crashed = True
                    self.log_crash()
                    self.time_to_crash = 0
                    self.application_crashes += 1
                    self.cds.reset()
                elif self.appstate2 == 'Normal':
                    self.app_is_crashed = False
                elif self.appstate2 == 'In_Single_Cycle':
                    self.app_is_crashed = False
                else:
                    print ("Unknown app state: %s %s" % (self.appstate, self.appstate2))

                # Measure iteration time
                iteration_start = time.time()

                # Execute one cycle or wait
                if not self.runtime_is_down and not self.app_is_crashed and self.appstate2 != 'In_Single_Cycle':
                    ans = self.cds.runSingleCycle()

                    if ans == 1:
                        self.iterCnt += 1
                        self.iter_skipped = False

                        # Generate inputs
                        # Old CmpFeeder way
                        # f = CmpFeeder(self.cds)
                        # f.fuz_cmpdevice()
                        # tags = f.fuz_cmpcoredump()

                        # Newer harnesses way
                        cmp = CmpFileTransfer()
                        service_id = cmp.SERVICE_ID
                        inj = "\x00"+os.urandom(20)+"\x00"
                        l7data, command_id = cmp.get_fileinfo(inj)

                        # Send L7 data and get response
                        L7 = layer7(service_id, command_id, self.cds.sess_id, l7data)
                        self.cds.send_layer7(L7)
                        tags = self.cds.recv_layer7()


                        #todo

                        print('reply:')
                        print(pretty_format_tagsdict(tags))

                        # Generate input

                        # pay="\x19\x00\x00\x00"
                        # payload = self.rad.fuzz(pay, seed=1337, max_mut=10)

                        # payload_len = random.randint(1,32)
                        payload_len = 4
                        payload = os.urandom(payload_len)
                        self.wrote_values = payload
                        # tags = f.fuz_recordadd(payload)
                        # print('reply:')
                        # print(pretty_format_tagsdict(tags))
                        #

                        # Finalise time
                        iteration_end = time.time()
                        self.total_time = iteration_end - total_time_start
                        self.iteration_time = iteration_end - iteration_start

                    else:
                        self.iter_skipped = True
                        print('Skipped iteration as SingleCycle failed: %d' % ans)

                if self.VERBOSE:
                    print('[*] Showing stats for iteration %d' % self.iterCnt)

                # Display stats
                if (self.iterCnt % self.STATS_SHOW_EVERY == 0):
                    self.show_stats()

                sleep(self.THROTTLE_S)

        except KeyboardInterrupt:
            print('Interrupted')
        except Exception as e:
            print('Exception')
            traceback.print_exc()
        finally:
            print('Exiting. Wait %d sec pls...' % self.SHUTDOWN_DELAY)
            sleep(self.SHUTDOWN_DELAY)
            self.cds.disconnect()
            print('Goodbye')
            # exit(0)


# Main


arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-t', '--just-test-inputs', action='store_true', default=False, help='Dry run: just test the inputs')

args = arg_parser.parse_args()
print(args)

fuzzer = CMPFuzzer()


if args.just_test_inputs:

    fuzzer.test_inputs()
else:
    fuzzer.run()
