(*#-#-#-#-#-#-#-#-#-#---Declaration---#-#-#-#-#-#-#-#-#-#-#-#-#*)

PROGRAM PLC_PRG
VAR
	text1: STRING(144);
	text2: STRING(192);
	BASE64_ENCODE_STR: BASE64_ENCODE_STR;
	start: BOOL := TRUE;
	done1: BOOL := FALSE;
END_VAR
/* This is a manually injected bug! */
// IF (LEN(text1) = 4 AND MID(text1, 4, 1) = 'asdf') THEN
// 	printf('Causing crash...(%s)$N', ADR(text1)*424242);
// END_IF;

BASE64_ENCODE_STR(RUN:=start, STR1:=text1, STR2:=text2, DONE:=done1);
// printf('(st)text1= %s$N', ADR(text1));
// printf('(st)text2= %s$N', ADR(text2));
END_PROGRAM


(*#-#-#-#-#-#-#-#-#-#---Declaration---#-#-#-#-#-#-#-#-#-#-#-#-#*)

FUNCTION_BLOCK BASE64_ENCODE_STREAM
VAR_IN_OUT
	BUF1 : ARRAY [0..47] OF BYTE;
	BUF2 : ARRAY [0..63] OF BYTE;
END_VAR
VAR_INPUT
	SIZE1 : INT;
END_VAR
VAR_OUTPUT
	SIZE2 : INT;
END_VAR
VAR
	a: INT;
	b: WORD;
	i: INT;
	i2: INT;
	i3: INT;
	c: INT;
	BASE64: STRING(64) := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
END_VAR

(*
version 1.0	06. dec. 2009
programmer 	ks
tested by	ks

BASE64_ENCODE_STREAM konvertiert Datenblöcke in Base64. 

*)

(*#-#-#-#-#-#-#-#-#-#---Implementation---#-#-#-#-#-#-#-#-#-#-#-#-#*)

IF SIZE1 <= 0 THEN
	SIZE2 := 0;
	RETURN;
END_IF;
c := SIZE1 - 1;
i2 := 0;
a := 0;
b := 0;
FOR i := 0 TO c DO
	b := SHL(b,8) OR BUF1[i];
	a := a + 8;
	WHILE a >= 6 DO
		a := a - 6;
		buf2[i2] := CODE(BASE64,WORD_TO_INT(SHR(b,a)) + 1);
		i2 := i2 + 1;
		b := b AND NOT SHL(WORD#16#FFFF,a);
	END_WHILE;
END_FOR;
IF a > 0 THEN
	buf2[i2] := CODE(BASE64,WORD_TO_INT(SHL(b,6 - a)) + 1);
	i2 := i2 + 1;
	i3 := i2 + (NOT INT_TO_WORD(i2) AND 2#11);
	FOR i := i2 TO i3 DO
		buf2[i] := 61;
	END_FOR;
	SIZE2 := i3 + 1;
ELSE
	SIZE2 := i2;
END_IF;
END_FUNCTION_BLOCK


(*#-#-#-#-#-#-#-#-#-#---Declaration---#-#-#-#-#-#-#-#-#-#-#-#-#*)

FUNCTION_BLOCK BASE64_ENCODE_STR
VAR_INPUT
	RUN : BOOL := TRUE;
END_VAR
VAR_OUTPUT
	DONE : BOOL;
END_VAR
VAR_IN_OUT
	STR1 : STRING(144);
	STR2 : STRING(192);
END_VAR
VAR
	BASE64_ENCODE_STREAM : BASE64_ENCODE_STREAM;
	run_last : BOOL;
	buf1 : ARRAY [0..47] OF BYTE;
	buf2 : ARRAY [0..63] OF BYTE;
	mode : INT;
	size1 : INT;
	size2 : INT;
	end : INT;
	pos : INT;
	myvar : STRING;
END_VAR

(*
version 1.0	06. dec. 2009
programmer 	ks
tested by	ks

BASE64_ENCODE_STR konvertiert einen normalen String in einen BASE64 kodierten String. 

*)


(*#-#-#-#-#-#-#-#-#-#---Implementation---#-#-#-#-#-#-#-#-#-#-#-#-#*)
IF RUN AND NOT run_last THEN
	DONE := FALSE;
	mode := 1;
	end := LEN(STR1);
	pos := 0;
	STR2 := '';
END_IF;

size1 := MIN(48,end - pos);
IF size1 > 0 THEN
	_STRING_TO_BUFFER(STR:=MID(STR1, size1, pos + 1), POS:=0, PT:=ADR(buf1), SIZE:=SIZEOF(buf1));
	BASE64_ENCODE_STREAM(BUF1:=buf1 ,BUF2:=buf2 ,SIZE1:=size1 ,SIZE2=>size2);
	__memcpy(dest:=ADR(STR2), src:=ADR(buf2), size:=size2);
ELSE
	mode := 0;
	DONE := TRUE;
END_IF;
pos := pos + size1;

run_last := RUN;

END_FUNCTION_BLOCK