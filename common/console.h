#ifndef _CONSOLE_H
#define _CONSOLE_H

#include <windows.h>

BOOL WriteLastSystemError(void);
BOOL WriteStdErr(LPCTSTR, ...);
BOOL WriteStdOut(LPCTSTR, ...);
BOOL WriteSystemError(DWORD);

#endif
