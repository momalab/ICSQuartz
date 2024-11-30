PROGRAM PLC_PRG
VAR
	input1 AT %IW1:WORD;
	output1 AT %QW1:WORD;
	in_addr: DWORD;
END_VAR
output1 := mmove_4(input1);
END_PROGRAM

FUNCTION mmove_4 : WORD

VAR_INPUT
	input1: WORD;
END_VAR

VAR
	locbuffer: WSTRING(128);
	locbuffer2: WSTRING(256);
	mov_val_1: WORD;
	mov_val_2: WORD;
	cond: WORD;
	address: DWORD;
END_VAR

locbuffer := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
locbuffer2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

//address := ADR(locbuffer);

mov_val_1 := input1/128 + 401;
mov_val_2 := input1/64 + 311;

cond := input1/256;

IF cond < 100 THEN
	SysMemMove(ADR(locbuffer2), ADR(locbuffer), mov_val_1);
ELSE
	SysMemMove(ADR(locbuffer2), ADR(locbuffer), mov_val_2);
END_IF

mmove_4 := cond;
END_FUNCTION
