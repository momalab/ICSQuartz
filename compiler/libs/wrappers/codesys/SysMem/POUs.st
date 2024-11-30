FUNCTION SysMemSet : POINTER TO BYTE
VAR_INPUT
    pDest : POINTER TO BYTE; // start of memory to set
    udiValue : UDINT; // value to set
    udiCount : __XWORD; // number of bytes to set
END_VAR

SysMemSet := __memset(pDest, udiValue, udiCount);

END_FUNCTION

FUNCTION SysMemCpy : POINTER TO BYTE
VAR_INPUT
    pDest : POINTER TO BYTE; // pointer to destination
    pSrc : POINTER TO BYTE; // pointer to source
    udiCount : __XWORD; // number of bytes to copy
END_VAR

SysMemCpy := memcpy(pDest, pSrc, udiCount);

END_FUNCTION

FUNCTION SysMemMove : POINTER TO BYTE
VAR_INPUT
    pDest : POINTER TO BYTE; // pointer to destination
    pSrc : POINTER TO BYTE; // pointer to source
    udiCount : __XWORD; // number of bytes to move
END_VAR

SysMemMove := memmove(pDest, pSrc, udiCount);

END_FUNCTION