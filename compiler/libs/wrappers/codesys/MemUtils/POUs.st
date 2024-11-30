FUNCTION MemSet : POINTER TO BYTE
VAR_INPUT
    pbyBuffer : POINTER TO BYTE; // start of memory to set
    byValue : BYTE; // value to set
    dwSize : DWORD; // number of bytes to set
END_VAR

MemSet := __memset(pbyBuffer, byValue, dwSize);

END_FUNCTION

FUNCTION BitCpy : BOOL
VAR_INPUT
    pDest : POINTER TO BYTE; // pointer to destination
    wDstStartBit : WORD; // start bit in destination
    pSource : POINTER TO BYTE; // pointer to source
    wSrcStartBit : WORD; // start bit in source
    wSize : WORD; // size in bits
END_VAR

BitCpy := __bitcpy(pDest, wDstStartBit, pSource, wSrcStartBit, wSize);

END_FUNCTION
