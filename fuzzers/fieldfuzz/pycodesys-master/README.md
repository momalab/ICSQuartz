pycodesys: CODESYS3 interaction library


References: 
- PoC for Tenable TRA-2020-04 https://www.tenable.com/security/research/tra-2020-04
- PoC for Tenable TRA-2020-46  https://www.tenable.com/security/research/tra-2020-46
- Project Basecamp for Codesys 2 https://github.com/digitalbond/Basecamp/blob/master/codesys-shell.py


## IEC_FUZZER usage
- Add to the CODESYSControl_User.cfg inside the VM:
[SysExcept]
EnableFirstLevelHandling=0
[CmpChannelServer]
MaxChannels = 1
- ./cds.sh inside the VM to launch wrapper and the runtime
- ./fuzz_iec.py ../../iec-projects/moma/bf_mcpy/bf_mcpy_1/profile.json
- see results/crashlog.txt
