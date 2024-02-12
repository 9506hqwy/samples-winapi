#pragma warning(once : 4710)
#pragma warning(once : 4711)

#include <windows.h>
#include <strsafe.h>
#include <tchar.h>
#include "console.h"

#define BUF_SIZE 16384

BOOL WriteOutput(DWORD, LPCTSTR, va_list);

BOOL WriteLastSystemError(void)
{
    return WriteSystemError(GetLastError());
}

BOOL WriteStdErr(LPCTSTR format, ...)
{
    va_list args = NULL;
    va_start(args, format);
    BOOL ret = WriteOutput(STD_ERROR_HANDLE, format, args);
    va_end(args);
    return ret;
}

BOOL WriteStdOut(LPCTSTR format, ...)
{
    va_list args = NULL;
    va_start(args, format);
    BOOL ret = WriteOutput(STD_OUTPUT_HANDLE, format, args);
    va_end(args);
    return ret;
}

BOOL WriteSystemError(DWORD code)
{
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    LPTSTR msg = NULL;

    if (!FormatMessage(flags, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&msg, 0, NULL))
    {
        WriteStdErr(_T("Error: %u\n"), code);
        return FALSE;
    }

    BOOL ret = WriteStdErr(_T("%u: %s"), code, msg);

    LocalFree(msg);

    return ret;
}

// -----------------------------------------------------------------------------------------------

BOOL WriteOutput(DWORD fd, LPCTSTR format, va_list args)
{
    TCHAR msg[BUF_SIZE] = {0};

    HRESULT ret = StringCbVPrintf(msg, BUF_SIZE * sizeof(TCHAR), format, args);
    if (FAILED(ret))
    {
        WriteStdErr(_T("Error: %u\n"), ret);
        return FALSE;
    }

    HANDLE handle = GetStdHandle(fd);
    DWORD written = 0;
    return WriteFile(handle, msg, lstrlen(msg) * sizeof(TCHAR), &written, NULL);
}
