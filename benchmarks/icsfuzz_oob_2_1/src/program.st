PROGRAM PLC_PRG
VAR
	input1 AT %IW1:WORD;
	output1 AT %QW1:WORD;
	in_addr: DWORD;
END_VAR
output1 := arr_1(input1);
END_PROGRAM    

FUNCTION arr_1 : WORD

VAR_INPUT
	input1: WORD;
END_VAR

VAR
	array1: ARRAY [0 .. 100] OF WORD;
	index: WORD;
	load_val: WORD;
END_VAR
load_val := 16#DEAD;

index := input1/256 + 32;

load_val:= array1[index];

arr_1 := index;
END_FUNCTION
