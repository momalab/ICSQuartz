PROGRAM PLC_PRG
VAR
	input1 AT %IW1:WORD;
	output1 AT %QW1:WORD;
	in_addr: DWORD;
END_VAR
output1 := mcpy_6(input1);
END_PROGRAM

FUNCTION mcpy_6 : WORD

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
	iter: DINT;
END_VAR

locbuffer := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
locbuffer2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

//address := ADR(locbuffer);

mov_val_1 := input1/128 + 32;
mov_val_2 := input1/64 - 17;

cond := input1/512; 

FOR iter := 0 TO 100 BY 1 DO
	IF iter < mov_val_1 THEN
		SysMemCpy(ADR(locbuffer2), ADR(locbuffer), mov_val_1);
	ELSE
		SysMemCpy(ADR(locbuffer2), ADR(locbuffer), mov_val_2);
	END_IF
END_FOR



mcpy_6 := cond;
END_FUNCTION
