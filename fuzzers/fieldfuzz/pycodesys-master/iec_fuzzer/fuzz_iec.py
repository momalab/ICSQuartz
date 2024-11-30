#! /usr/bin/env python2
import datetime
import json
import os, sys, time, logging, traceback
from random import choice
from time import sleep

sys.path.append("..")
from lib.pycodesys import CodesysNode, VMeta, CDS_WORD, CDS_INT, CDS_SIZE, CDS_TYPE_IDS
from feeder_modbus import ModbusFeeder
from feeder_mon2 import Mon2Feeder

# from profiles import prashant3 as prg_profile


"""
Fuzzer for IEC application variables
Keepalive interval = 1000 ms
"""

# Log all inputs to a file
fuzzer_stats_log = open("/fuzzer_stats.log", "a+")


class IECFuzzer:
    l = None
    cds = None
    iterCnt = 0
    appname = ""
    appstate = "Checking"
    appstate2 = "Checking"
    app_exec_pos = ""
    total_time = 0
    iteration_time = 0
    time_to_crash = 0
    application_crashes = 0
    # runtime_crashes=0
    previous_appstate = ""
    previous_appstate2 = ""
    # retrieved_values = None
    wrote_values = None
    app_is_crashed = False
    runtime_is_down = False
    iter_skipped = False
    valid_area0_start = 0
    prg_profile = {}
    STATS_SHOW_EVERY = 1
    THROTTLE_S = 0.0
    SHUTDOWN_DELAY = 2
    VERBOSE = False
    last_cmd_failed = False
    last_iter_shown = -1

    # LOG_F = 'log.txt'

    def __init__(self):
        # Init logger and stats
        self.l = logging.getLogger("fuzz_iec")
        lhandler = logging.StreamHandler()
        lhandler.setLevel(logging.DEBUG)
        self.l.addHandler(lhandler)

        # logging.StreamHandler().setLevel(logging.DEBUG)
        # self.l.setLevel(logging.DEBUG)

        # self.stats={
        #     'iterCnt':1,
        #     'status':'',
        #     'appname':''
        #     }

        self.l.debug("[*] IECFuzzer initialized")

    def show_stats(self):
        T_GREEN = "\033[92m"
        T_YELLOW = "\33[33m"
        T_ENDC = "\033[0m"
        T_RED = "\033[91m"
        # if not self.VERBOSE:
        #     os.system('clear')

        if self.appstate2 == "Normal":
            statetext = T_GREEN + self.appstate + T_ENDC
            state2text = T_GREEN + self.appstate2 + T_ENDC
        elif self.appstate2 == "Exception":
            statetext = T_RED + self.appstate + T_ENDC
            state2text = T_RED + self.appstate2 + T_ENDC
        else:
            statetext = T_YELLOW + self.appstate + T_ENDC
            state2text = T_YELLOW + self.appstate2 + T_ENDC

        ts = time.time()
        fuzzer_stats_log.write(
            "{}: Iteration: #{} :: Crashes: {} :: Input {}\n".format(
                ts, self.iterCnt, self.application_crashes, self.wrote_values
            )
        )
        fuzzer_stats_log.flush()

        print("\n|-- --- ---")
        print("|-- Fuzzing ---")
        print(
            "|-- Iteration: #{}  :: Crashes: {} :: Status: [{}] [{}]".format(
                self.iterCnt, self.application_crashes, statetext, state2text
            )
        )
        print(
            "|-- Total time: %.3f s :: TTC: %.3f ms :: Iteration time: %.3f ms"
            % (self.total_time, self.time_to_crash * 1000, self.iteration_time * 1000)
        )
        print("|-- Wrote: %s" % self.wrote_values)
        print("|-- --- ---")
        print(
            "|-- App name: %s :: Chan: %02x :: Area: %s"
            % (self.appname, self.cds.chan_id, hex(self.valid_area0_start))
        )
        print(
            "|-- Status change: %s %s --> %s %s"
            % (
                self.previous_appstate,
                self.previous_appstate2,
                self.appstate,
                self.appstate2,
            )
        )
        print(
            "|-- Exception detected: %s :: Pos: %s"
            % (self.app_is_crashed, self.app_exec_pos)
        )
        print(
            "|-- Runtime down: %s :: Throttling: %.1f ms"
            % (self.runtime_is_down, self.THROTTLE_S * 1000)
        )
        print("|-- --- ---\n")
        if self.app_is_crashed:
            print("\n\n ** APP CRASHED. Needs reset **\n\n")

        if self.runtime_is_down:
            print("\n\n ** RUNTIME IS DOWN. Needs restart **\n\n")

        if self.iter_skipped:
            print("\n\n ** ON HOLD **\n\n")

    def read_appstates(self):

        if self.cds.blk_failure:
            return None

        self.previous_appstate = self.appstate
        self.previous_appstate2 = self.appstate2

        self.appstate = "Checking"
        self.appstate2 = "Checking"

        st = self.cds.readAppStatus()
        if st:
            self.appstate, self.appstate2, self.app_exec_pos = st
            return self.appstate
        else:
            return None

    """
    Checks
    """

    # def runtime_healtcheck(self):
    #     if self.cds.blk_failure:
    #         self.runtime_is_down = True
    #     else:
    #         self.runtime_is_down = False
    #     return self.runtime_is_down

    def create_profile_from_json(self, profile_data):
        varlist = []
        for v in profile_data["variables"]:
            type_id = CDS_TYPE_IDS[v["var_type"]]
            varlist.append(
                VMeta(name=v["var_name"], type=type_id, offset=v["var_offset"])
            )
        self.prg_varlist = varlist

    def pretest_profile(self, p):
        print("\n[*] Pretesting profile...")

        # Check var offsets sanity
        for num, v in enumerate(self.prg_varlist):
            if (v.offset > 65535) or (v.offset <= 0):
                print("[-] read_variables: variable %d offset is wrong!" % num)
                return False
        # Read
        read_vars = None
        # read_vars = self.cds.read_variables(self.prg_varlist)
        print("[*] Pretest: Profile read: " + str(read_vars))

        # Write
        new_values = []
        for var in self.prg_varlist:
            byte_of_choice = choice(["\xCC", "\xDD", "\xEE", "\xBA", "\xAB"])
            to_write = byte_of_choice * CDS_SIZE[var.type]
            new_values.append(to_write)
            print(
                "** GONNA WRITE: HEX: %s TO OFFSET: %s"
                % (to_write.encode("hex"), hex(var.offset))
            )
        # Write list of vars
        res = self.cds.write_variables(
            self.prg_varlist, values=new_values, is_raw_bytestr=True
        )
        if not res:
            print(
                "[-] Pretest: Write failed. Are var offsets and the magic sequences correct?"
            )
            return False
        print(
            "[*] Pretest: Profile write: fill vars with 0x%s"
            % byte_of_choice.encode("hex")
        )

        # Read again
        read_vars = None
        read_vars = self.cds.read_variables(self.prg_varlist)
        print("[*] Pretest: Profile read again: " + str(read_vars))

        return True

    """
    Inputs
    """

    def generate_inputs(self, varlist):
        res = []
        for var in varlist:
            res.append(os.urandom(CDS_SIZE[var.type]))
        return res

    def stringify_inputs(self, inputslist):
        res = []
        for num, var in enumerate(inputslist):
            res.append(str(num) + " : " + var.encode("hex"))
        return res

    """
    Events
    """

    def log_crash(self):

        print("[*] logging crash")

        # Log
        if not os.path.exists("results/"):
            os.makedirs("results/")
        with open("results/crashlog.txt", "a") as logfile:
            ts = time.time()
            st = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            logfile.write(
                " %s Crash. Application: %s. Iteration: %d. To crash: %.3f ms. Iteration time: %.3f ms. Inputs: %s \n"
                % (
                    st,
                    self.appname,
                    self.iterCnt,
                    self.time_to_crash * 1000,
                    self.iteration_time * 1000,
                    self.wrote_values,
                )
            )

    """
    Run
    """

    def run(self):
        # Create connection
        self.cds = CodesysNode(host="127.0.0.1", port=11740, verbose=self.VERBOSE)
        if not self.cds.connect():
            exit("[-] Cannot connect. Is runtime down?")

        self.cds.loginToDevice()

        # Find loaded application
        self.appname = self.cds.readAppList()
        if len(self.appname) > 3:
            self.l.debug("Found application: " + self.appname)

        self.cds.loginToApp(self.appname)

        self.valid_area0_start = self.cds.getAreaAddress()

        # Start application
        # self.cds.start()

        # print('Resetting')
        # self.cds.reset_c()

        print("[*] Stopping the application")
        self.cds.stop()

        """
        Main fuzz loop
        """

        if not self.prg_varlist:
            exit("No application profile")

        # Measure iteration time
        total_time_start = time.time()
        self.no_crash_since = total_time_start

        try:
            # Pretest
            if not self.pretest_profile(self.prg_profile):
                print("[-] Profile is wrong")
                self.cds.disconnect()
            else:
                print("[+] Profile pretest: no errors")
                # raw_input("\nLooks correct? Enter to continue...\n")

            # Fuzz loop
            while True:
                if self.VERBOSE:
                    print("[*] --- Iteration %d ---" % self.iterCnt)

                # Read runtime state, reconnect
                if self.cds.blk_failure:
                    if self.VERBOSE:
                        print("reconnecting to runtime... %s", self.cds.blk_failure)
                    self.appstate = "Recovering"
                    self.appstate2 = "Recovering"
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
                        self.l.debug("Found application: " + self.appname)
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
                if self.appstate2 == "Exception":
                    self.app_is_crashed = True
                    self.log_crash()
                    self.time_to_crash = 0
                    self.application_crashes += 1
                    self.cds.reset()
                elif self.appstate2 == "Normal":
                    self.app_is_crashed = False
                elif self.appstate2 == "In_Single_Cycle":
                    self.app_is_crashed = False
                else:
                    print("Unknown app state: %s %s" % (self.appstate, self.appstate2))

                # Measure iteration time
                iteration_start = time.time()

                # Execute one cycle or wait
                if (
                    not self.runtime_is_down
                    and not self.app_is_crashed
                    and self.appstate2 != "In_Single_Cycle"
                ):
                    ans = self.cds.runSingleCycle()

                    if ans == 1:
                        self.iterCnt += 1
                        self.iter_skipped = False

                        # Write values
                        new_values = self.generate_inputs(self.prg_varlist)
                        self.cds.write_variables(
                            self.prg_varlist, values=new_values, is_raw_bytestr=True
                        )
                        self.wrote_values = self.stringify_inputs(new_values)

                        # Finalise time
                        iteration_end = time.time()
                        self.total_time = iteration_end - total_time_start
                        self.iteration_time = iteration_end - iteration_start

                    else:
                        self.iter_skipped = True
                        print("Skipped iteration as SingleCycle failed: %d" % ans)

                if self.VERBOSE:
                    print("[*] Showing stats for iteration %d" % self.iterCnt)

                # Display stats
                if (
                    self.iterCnt % self.STATS_SHOW_EVERY == 0
                    and self.iterCnt != self.last_iter_shown
                ):
                    self.last_iter_shown = self.iterCnt
                    self.show_stats()

                sleep(self.THROTTLE_S)

        except KeyboardInterrupt:
            print("Interrupted")
        except Exception as e:
            print("Exception")
            traceback.print_exc()
        finally:
            print("Exiting. Wait %d sec pls..." % self.SHUTDOWN_DELAY)
            sleep(self.SHUTDOWN_DELAY)
            self.cds.disconnect()
            print("Goodbye")
            # exit(0)


# Main

if len(sys.argv) != 2:
    print("Usage: ./fuzz_iec.py profile.json")
    exit()

# Read profile file
fpath = sys.argv[1]
if not os.path.isfile(fpath):
    print("No such file: " + fpath)
    exit()

with open(fpath, "r") as pf:
    profile_data = json.load(pf)

# Create fuzzer
fuzzer = IECFuzzer()
fuzzer.create_profile_from_json(profile_data)
fuzzer.run()
