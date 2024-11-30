PROGRAM PLC_PRG
VAR
	input1 AT %IW1:WORD;
	output1 AT %QW1:WORD;
	in_addr: DWORD;
END_VAR
output1 := mcpy_1(input1);
END_PROGRAM

FUNCTION mcpy_1 : WORD

VAR_INPUT
	input1: WORD;
END_VAR

VAR
	locbuffer: WSTRING(128);
	locbuffer2: WSTRING(256);
	mov_val: WORD;
	address: DWORD;
END_VAR

locbuffer := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
locbuffer2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

//address := ADR(locbuffer);

mov_val := input1/128 + 124;

SysMemCpy(ADR(locbuffer2), ADR(locbuffer), mov_val);


mcpy_1 := mov_val;
END_FUNCTION
