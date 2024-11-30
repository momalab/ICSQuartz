PROGRAM PLC_PRG
VAR
	input1 AT %IW1:WORD;
	output1 AT %QW1:WORD;
	in_addr: DWORD;
END_VAR
output1 := mset_3(input1);
END_PROGRAM

FUNCTION mset_3 : WORD

VAR_INPUT
	input1: WORD;
END_VAR

VAR
	locbuffer: WSTRING(128);
	mov_val: WORD;
	cond: WORD;
	address: DWORD;
END_VAR


locbuffer := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

mov_val := input1/64 + 115;

//address := ADR(locbuffer);

cond := input1/128;

IF cond > 100 THEN
	SysMemSet(ADR(locbuffer), 6666, mov_val);
END_IF

mset_3 := mov_val;

END_FUNCTION