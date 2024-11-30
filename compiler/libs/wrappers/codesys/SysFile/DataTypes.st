TYPE SysFile__SYS_FILE_STATUS :
(
   FS_OK := 0,         (* File could be opened *)
   FS_NO_FILE := 1,    (* No file available *)
   FS_ILLEGAL_POS := 2,(* Illegal position in the file *)
   FS_FULL := 3,       (* No more space on the filesystem *)
   FS_EOF := 4         (* End of file reached *)
);
END_TYPE

TYPE ACCESS_MODE :
(
  AM_READ := 0,       (* Open an existing file with Read access. If file does not exist, Open fails *)
  AM_WRITE := 1,      (* Create new file with Write access. If file does exist, content is discarded *)
  AM_APPEND := 2,     (* Open an existing file with Append (only write) access. If file does not exist, Open fails *)
  AM_READ_PLUS := 3,  (* Open an existing file with Read/Write access. If file does not exist, Open fails *)
  AM_WRITE_PLUS := 4, (* Create new file with Read/Write access. If file does exist, content is discarded *)
  AM_APPEND_PLUS := 5 (* Open an existing file with Append (read/write) access. If file does not exist, Open creates a new file *)
);
END_TYPE

// https://content.helpme-codesys.com/en/libs/SysTypes2%20Interfaces/Current/RTS_IEC_RESULT.html
TYPE SysFile__RTS_IEC_RESULT : UDINT;
END_TYPE

TYPE SysFile__RTS_IEC_HANDLE : POINTER TO BYTE;
END_TYPE

TYPE RTS_IEC_HANDLE : POINTER TO BYTE;
END_TYPE

TYPE RTS_IEC_RESULT : UDINT;
END_TYPE
