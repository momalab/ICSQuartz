PROGRAM PLC_PRG
VAR
	input1 AT %IW1:WORD;
	output1 AT %QW1:WORD;
	in_addr: DWORD;
END_VAR
output1 := arr_5(input1);
END_PROGRAM

FUNCTION arr_5 : WORD

VAR_INPUT
	input1: WORD;
END_VAR

VAR
	array1: ARRAY [0 .. 100] OF WORD;
	index: WORD;
	load_val: WORD;
	iter: DINT;
	cond: WORD;
END_VAR

load_val := 16#DEAD;

index := input1/256 + 32;

cond := input1/512;

FOR iter := 0 TO 100 BY 1 DO
	IF iter > cond THEN
		load_val:= array1[index];
	END_IF
END_FOR

arr_5 := index;
END_FUNCTION