FUNCTION SysSockAccept : DINT
VAR_INPUT
    diSocket : DINT;
    pSockAddr : DWORD;  // Address of SocketAddress (SOCKADDRESS)
    piSockAddrSize : DWORD;  // Address of socket address size (DINT)
END_VAR

unimplemented('SysSockAccept');
END_FUNCTION

FUNCTION SysSockBind : BOOL
VAR_INPUT
    diSocket : DINT;
    pSockAddr : DWORD;  // Address of SocketAddress (SOCKADDRESS)
    diSockAddrSize : DINT;  // Size of socket address
END_VAR

unimplemented('SysSockBind');
END_FUNCTION

FUNCTION SysSockClose : BOOL
VAR_INPUT
    diSocket : DINT;
END_VAR

unimplemented('SysSockClose');
END_FUNCTION

FUNCTION SysSockConnect : BOOL
VAR_INPUT
    diSocket : DINT;
    pSockAddr : DWORD;  // Address of SocketAddress (SOCKADDRESS)
    diSockAddrSize : DINT;  // Size of socket address
END_VAR

unimplemented('SysSockConnect');
END_FUNCTION

FUNCTION SysSockCreate : DINT
VAR_INPUT
    diAddressFamily : DINT;
    diType : DINT;
    diProtocol : DINT;
END_VAR

unimplemented('SysSockCreate');
END_FUNCTION

FUNCTION SysSockGetHostByName : DWORD
VAR_INPUT
    stHostName : STRING;
END_VAR

unimplemented('SysSockGetHostByName');
END_FUNCTION


FUNCTION SysSockGetHostName : BOOL
VAR_INPUT
    diNameLength : DINT;
END_VAR
VAR_IN_OUT
    stHostName : STRING;
END_VAR

unimplemented('SysSockGetHostName');
END_FUNCTION


FUNCTION_BLOCK SysSockGetLastError
VAR_INPUT
    bEnable : BOOL;
    diSocket : DINT;
END_VAR
VAR_OUTPUT
    bDone : BOOL;
    bBusy : BOOL;
    bError : BOOL;
    wErrorId : WORD;
    dwLastError : DWORD;
END_VAR

unimplemented('SysSockGetLastError');
END_FUNCTION_BLOCK


FUNCTION SysSockGetLastErrorSync : DINT
VAR_INPUT
    diSocket : DINT;
END_VAR

unimplemented('SysSockGetLastErrorSync');
END_FUNCTION


FUNCTION SysSockGetOption : BOOL
VAR_INPUT
    diSocket : DINT;
    diLevel : DINT;
    diOption : DINT;
    pOptionValue : DWORD;    // Address of option
    piOptionLength : DWORD;  // Address of option size (DINT)
END_VAR

unimplemented('SysSockGetOption');
END_FUNCTION


FUNCTION SysSockHtonl : DWORD
VAR_INPUT
    dwHost : DWORD;
END_VAR

unimplemented('SysSockHtonl');
END_FUNCTION


FUNCTION SysSockHtons : WORD
VAR_INPUT
    wHost : WORD;
END_VAR

unimplemented('SysSockHtons');
END_FUNCTION


FUNCTION SysSockInetAddr : DWORD
VAR_IN_OUT
    stIPAddr : STRING;
END_VAR

unimplemented('SysSockInetAddr');
END_FUNCTION


FUNCTION SysSockInetNtoa : BOOL
VAR_INPUT
    InAddr : INADDR;
    diIPAddrSize : DINT;
END_VAR
VAR_IN_OUT
    stIPAddr : STRING;
END_VAR

unimplemented('SysSockInetNtoa');
END_FUNCTION


FUNCTION SysSockIoctl : DINT
VAR_INPUT
    diSocket : DINT;
    diCommand : DINT;
    piParameter : DWORD; // Address of parameter (DINT)
END_VAR

unimplemented('SysSockIoctl');
END_FUNCTION


FUNCTION SysSockListen : BOOL
VAR_INPUT
    diSocket : DINT;
    diMaxConnections : DINT;
END_VAR

unimplemented('SysSockListen');
END_FUNCTION


FUNCTION SysSockNtohl : DWORD
VAR_INPUT
    dwNet : DWORD;
END_VAR

unimplemented('SysSockNtohl');
END_FUNCTION



FUNCTION SysSockNtohs : WORD
VAR_INPUT
    wNet : WORD;
END_VAR

unimplemented('SysSockNtohs');
END_FUNCTION


FUNCTION SysSockSelect : DINT
VAR_INPUT
    diWidth : DINT;        // Typically SOCKET_FD_SETSIZE
    fdRead : DWORD;        // Address of SOCKET_FD_SET
    fdWrite : DWORD;       // Address of SOCKET_FD_SET
    fdExcept : DWORD;      // Address of SOCKET_FD_SET
    ptvTimeout : DWORD;    // Address of SOCKET_TIMEVAL
END_VAR

// This routine permits a task to pend until one of a set of sockets handles becomes ready.
// Three parameters – fdRead, fdWrite and fdExcept – point to file descriptor sets in which each array entry corresponds to a particular socket handle.
// If a socket handle is not ready, it will be written in the array to -1 (SOCKET_INVALID).
// With the timeout value, a timeout for the operation can be specified. diWidth is the size of the fd_array array in SOCKETFD_SET.
// The function returns the operating system result.
// <0: Error 0: Timeout expired >0: Typically number of sockets that are successfully selected
unimplemented('SysSockSelect');
END_FUNCTION


FUNCTION SysSockSetIPAddress : BOOL
VAR_INPUT
    stCardName : STRING;     // Card Name
    stIPAddress : STRING;    // IP Address
END_VAR

unimplemented('SysSockSetIPAddress');
END_FUNCTION


FUNCTION SysSockSetOption : BOOL
VAR_INPUT
    diSocket : DINT;            // Socket
    diLevel : DINT;             // Level
    diOption : DINT;            // Option
    pOptionValue : DWORD;       // Address of option
    diOptionLength : DINT;      // Length of option
END_VAR

unimplemented('SysSockSetOption');
END_FUNCTION


FUNCTION SysSockShutdown : BOOL
VAR_INPUT
    diSocket : DINT;   // Socket
    diHow : DINT;      // How
END_VAR

unimplemented('SysSockShutdown');
END_FUNCTION


FUNCTION SysSockRecv : DINT
VAR_INPUT
    diSocket : DINT;         // Socket
    pbyBuffer : DWORD;       // Address of buffer to receive
    diBufferSize : DINT;     // Buffer Size
    diFlags : DINT;          // Flags
END_VAR

unimplemented('SysSockRecv');
END_FUNCTION


FUNCTION SysSockSend : DINT
VAR_INPUT
    diSocket : DINT;         // Socket
    pbyBuffer : DWORD;       // Address of buffer to send
    diBufferSize : DINT;     // Buffer Size
    diFlags : DINT;          // Flags
END_VAR

unimplemented('SysSockSend');
END_FUNCTION

FUNCTION SysSockRecvFrom : DINT
VAR_INPUT
    diSocket : DINT;         // Socket
    pbyBuffer : DWORD;       // Address of buffer to receive
    diBufferSize : DINT;     // Buffer Size
    diFlags : DINT;          // Flags
    pSockAddr : DWORD;       // Address of socket address SOCKADDRESS
    diSockAddrSize : DINT;   // Size of socket address
END_VAR

unimplemented('SysSockRecvFrom');
END_FUNCTION


FUNCTION SysSockSendTo : DINT
VAR_INPUT
    diSocket : DINT;         // Socket
    pbyBuffer : DWORD;       // Address of buffer to receive
    diBufferSize : DINT;     // Buffer Size
    diFlags : DINT;          // Flags
    pSockAddr : DWORD;       // Address of socket address SOCKADDRESS
    diSockAddrSize : DINT;   // Size of socket address
END_VAR

unimplemented('SysSockSendTo');
END_FUNCTION

