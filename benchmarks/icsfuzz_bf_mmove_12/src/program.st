PROGRAM PLC_PRG
VAR
	input1 AT %IW1:WORD;
	output1 AT %QW1:WORD;
	in_addr: DWORD;
END_VAR
output1 := mmove_12(input1);
END_PROGRAM

FUNCTION mmove_12 : WORD

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
	iter: DINT;
	ret_val: WORD;
END_VAR
locbuffer := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
locbuffer2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

//address := ADR(locbuffer);

mov_val_1 := input1/128 + 398;
mov_val_2 := input1/64 + 289;

cond1 := input1/64;
cond2 := input1/128 + 83;

FOR iter:=0 TO 100	BY 1 DO
	IF cond1 < iter THEN
		IF cond2 > 102 THEN
			SysMemMove(ADR(locbuffer2), ADR(locbuffer), mov_val_1);
		END_IF
	ELSE
		IF cond2 < 129 THEN
			ret_val := func_12(input1);
		END_IF
	END_IF
END_FOR

mmove_12 := cond1;
END_FUNCTION

FUNCTION func_12 : WORD

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
	iter: DINT;
END_VAR
locbuffer := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
locbuffer2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

//address := ADR(locbuffer);

mov_val_1 := input1/128 + 404;
mov_val_2 := input1/64 + 305;

cond1 := input1/64;
cond2 := input1/128 + 82;

FOR iter:=0 TO 100	BY 1 DO
	IF cond1 < iter THEN
		IF cond2 > 106 THEN
			SysMemMove(ADR(locbuffer2), ADR(locbuffer), mov_val_1);
		END_IF
	ELSE
		IF cond2 < 124 THEN
			SysMemMove(ADR(locbuffer2), ADR(locbuffer), mov_val_2);
		END_IF
	END_IF
END_FOR

func_12 := cond1;
END_FUNCTION
