#ifndef _CONSOLE_H
#define _CONSOLE_H

#include <windows.h>

BOOL WriteLastSystemError(void);
BOOL WriteStdErr(LPCTSTR, ...);
BOOL WriteStdOutA(LPCSTR, ...);
BOOL WriteStdOutW(LPCWSTR, ...);
BOOL WriteSystemError(DWORD);


#ifdef UNICODE
#define WriteStdOut WriteStdOutW
#else
#define WriteStdOut WriteStdOutA
#endif

#endif
