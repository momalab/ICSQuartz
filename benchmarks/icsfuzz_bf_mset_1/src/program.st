PROGRAM PLC_PRG
VAR
	input1 AT %IW1:WORD;
	output1 AT %QW1:WORD;
	in_addr: DWORD;
END_VAR
output1 := mset_1(input1);
END_PROGRAM

FUNCTION mset_1 : WORD

VAR_INPUT
	input1: WORD;
END_VAR

VAR
	locbuffer: WSTRING(128);
	mov_val: WORD;
	address: DWORD;
END_VAR


locbuffer := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

//address := ADR(locbuffer);

mov_val := input1/128 + 214;

SysMemSet(ADR(locbuffer), 6666, mov_val);

mset_1 := mov_val;
END_FUNCTION