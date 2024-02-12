#ifndef _STRING_H
#define _STRING_H

#include <windows.h>

BOOL WideToMB(HANDLE, LPCWSTR, LPSTR *);
BOOL MBToWide(HANDLE, LPCSTR, LPWSTR *);
BOOL SubStringW(HANDLE, LPCWSTR, DWORD, LPWSTR *);

#endif
