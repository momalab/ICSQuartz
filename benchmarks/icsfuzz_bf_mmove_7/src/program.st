PROGRAM PLC_PRG
VAR
	input1 AT %IW1:WORD;
	output1 AT %QW1:WORD;
	in_addr: DWORD;
END_VAR
output1 := mmove_7(input1);
END_PROGRAM

FUNCTION mmove_7 : WORD

VAR_INPUT
	input1: WORD;
END_VAR

VAR
	locbuffer: WSTRING(128);
	locbuffer2: WSTRING(256);
	mov_val_1: WORD;
	mov_val_2: WORD;
	cond1: WORD;
	cond2: WORD;
	address: DWORD;
	iter: WORD;
END_VAR

locbuffer := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
locbuffer2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

//address := ADR(locbuffer);

mov_val_1 := input1/128 + 384;
mov_val_2 := input1/64 + 295;

cond1 := input1/128;	
cond2 := input1/128 + 178;

IF cond1 < 100 THEN
	IF cond2 < 254 THEN
		SysMemMove(ADR(locbuffer2), ADR(locbuffer), mov_val_1);
	END_IF
ELSE
	IF cond2 > 397 THEN
		SysMemMove(ADR(locbuffer2), ADR(locbuffer), mov_val_2);
	END_IF
END_IF

mmove_7 := cond1;
END_FUNCTION