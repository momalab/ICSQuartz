// /****************************************
// Author: Corban Villa
// Date: June 16, 2023
// Description: This file will wrap the SysFile library
// Docs: https://help.codesys.com/webapp/idx-SysFile-lib;product=SysFile;version=3.5.17.0
// *****************************************/

// // This file will wrap fopen
// // https://help.codesys.com/webapp/SysFileOpen;product=SysFile;version=3.5.17.0
// FUNCTION SysFileOpen : SysFile__RTS_IEC_HANDLE
// VAR_INPUT
//    szFile : STRING; // file name to read
//    am : ACCESS_MODE;
//    pResult : POINTER TO SysFile__RTS_IEC_RESULT;
// END_VAR
// VAR
//    file: STRING;
//    modeString : STRING;
//    pFileData: POINTER TO BYTE;
// END_VAR
// CASE am OF
//    AM_READ:
//       modeString := 'r';
//    AM_WRITE:
//       modeString := 'w';
//    AM_APPEND:
//       modeString := 'a';
//    AM_READ_PLUS:
//       modeString := 'r+';
//    AM_WRITE_PLUS:
//       modeString := 'w+';
//    AM_APPEND_PLUS:
//       modeString := 'a+';
// END_CASE
// pFileData := __fopen(szFile, modeString);
// // Technically we do not need this conditional, if 
// // SysFile__RTS_INVALID_HANDLE is 0, but it is here for clarity
// IF pFileData = 0 THEN
//    pFileData := SysFile__RTS_INVALID_HANDLE;
// END_IF
// SysFileOpen := pFileData;
// END_FUNCTION

// // https://help.codesys.com/webapp/SysFileRead;product=SysFile;version=3.5.17.0
// FUNCTION SysFileRead : __XWORD
// VAR_INPUT
//    hFile : SysFile__RTS_IEC_HANDLE;
//    pbyBuffer : POINTER TO BYTE;
//    ulSize : __XWORD;
//    pResult : POINTER TO SysFile__RTS_IEC_RESULT;
// END_VAR
// SysFileRead := __fread(pbyBuffer, 1, ulSize, hFile);
// END_FUNCTION

// // https://help.codesys.com/webapp/SysFileClose;product=SysFile;version=3.5.17.0
// FUNCTION SysFileClose : SysFile__RTS_IEC_RESULT
// VAR_INPUT
//    hFile : SysFile__RTS_IEC_HANDLE;
// END_VAR
// SysFileClose := __fclose(hFile);
// END_FUNCTION

// FUNCTION SysFileWrite : __XWORD
// VAR_INPUT
//     hFile : RTS_IEC_HANDLE;           // Handle of the file
//     pbyBuffer : POINTER TO BYTE;      // Pointer to buffer with data to write to file
//     ulSize : __XWORD;                 // Number of bytes to write in the file. Must be less or equal the buffer size!
//     pResult : POINTER TO RTS_IEC_RESULT; // Pointer to runtime system error code
// END_VAR

// unimplemented('SysFileWrite');
// END_FUNCTION


// FUNCTION SysFileSetPos : RTS_IEC_RESULT
// VAR_INPUT
//     hFile : RTS_IEC_HANDLE;          // Handle of the file
//     ulOffset : __XWORD;              // Offset to set from the beginning of the file
// END_VAR

// unimplemented('SysFileSetPos');
// END_FUNCTION

// FUNCTION SysFileGetPos : RTS_IEC_RESULT
// VAR_INPUT
//     hFile : RTS_IEC_HANDLE;       // Handle of the file
//     pulPos : POINTER TO __XWORD;  // Pointer to get actual position of the file pointer from the beginning of the file
// END_VAR

// unimplemented('SysFileGetPos');
// END_FUNCTION


// FUNCTION SysFileDelete : RTS_IEC_RESULT
// VAR_INPUT
//     szFileName : STRING; // File name. Can contain absolute or relative path separated with a Slash (/)
// END_VAR

// unimplemented('SysFileDelete');
// END_FUNCTION

// FUNCTION SysFileGetSize : __XWORD
// VAR_INPUT
//     szFileName : STRING;        // File name. Can contain absolute or relative path separated with a Slash (/)
//     pResult : POINTER TO RTS_IEC_RESULT; // Pointer to runtime system error code
// END_VAR

// unimplemented('SysFileGetSize');
// END_FUNCTION
