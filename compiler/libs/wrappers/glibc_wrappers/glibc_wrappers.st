{external}
FUNCTION printf : DINT
VAR_INPUT {ref}
  format : STRING;
END_VAR
VAR_INPUT
  args : ...;
END_VAR
END_FUNCTION

{external}
FUNCTION __fopen : POINTER TO BYTE
VAR_INPUT {ref}
   szFile : STRING;
   modeString : STRING;
END_VAR
END_FUNCTION

{external}
FUNCTION __fread : __XWORD
VAR_INPUT
   ptr : POINTER TO BYTE;
   size : __XWORD;
   nitems: __XWORD;
   stream : POINTER TO BYTE;
END_VAR
END_FUNCTION

{external}
FUNCTION __fclose : DINT
VAR_INPUT
   hFile : POINTER TO BYTE; 
END_VAR
END_FUNCTION

{external}
FUNCTION __memcpy : POINTER TO BYTE
VAR_INPUT
   dest : POINTER TO BYTE;
   src : POINTER TO BYTE;
   size : __XWORD;
END_VAR
END_FUNCTION

{external}
FUNCTION memcpy : POINTER TO BYTE
VAR_INPUT
   dest : POINTER TO BYTE;
   src : POINTER TO BYTE;
   size : __XWORD;
END_VAR
END_FUNCTION

{external}
FUNCTION __memset : POINTER TO BYTE
VAR_INPUT
   dest : POINTER TO BYTE;
   char : UDINT;
   size : __XWORD;
END_VAR
END_FUNCTION

{external}
FUNCTION memmove : POINTER TO BYTE
VAR_INPUT
   dest : POINTER TO BYTE;
   src : POINTER TO BYTE;
   size : __XWORD;
END_VAR
END_FUNCTION

{external}
FUNCTION unimplemented
VAR_INPUT {ref}
   func_name: STRING;
END_VAR
END_FUNCTION

{external}
FUNCTION read_array
VAR_INPUT
   dest: POINTER TO BYTE;
   size : __XWORD;
END_VAR
END_FUNCTION

{external}
FUNCTION __bitcpy : BOOL
VAR_INPUT
    pDest : POINTER TO BYTE; // pointer to destination
    wDstStartBit : WORD; // start bit in destination
    pSource : POINTER TO BYTE; // pointer to source
    wSrcStartBit : WORD; // start bit in source
    wSize : WORD; // size in bits
END_VAR
END_FUNCTION

{external}
FUNCTION GetCodePointer : POINTER TO LINT
END_FUNCTION

{external}
FUNCTION StartPerfTimer : VOID
END_FUNCTION