#pragma warning(once : 4710)
#pragma warning(once : 4711)

#include <windows.h>
#include <strsafe.h>
#include "console.h"
#include "string.h"

#define BUF_SIZE 16384

BOOL WriteOutputA(DWORD, LPCSTR, va_list);
BOOL WriteOutputW(DWORD, LPCWSTR, va_list);

#ifdef UNICODE
#define WriteOutput WriteOutputW
#else
#define WriteOutput WriteOutputA
#endif

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

BOOL WriteStdOutA(LPCSTR format, ...)
{
    va_list args = NULL;
    va_start(args, format);
    BOOL ret = WriteOutputA(STD_OUTPUT_HANDLE, format, args);
    va_end(args);
    return ret;
}

BOOL WriteStdOutW(LPCWSTR format, ...)
{
    va_list args = NULL;
    va_start(args, format);
    BOOL ret = WriteOutputW(STD_OUTPUT_HANDLE, format, args);
    va_end(args);
    return ret;
}

BOOL WriteSystemError(DWORD code)
{
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    LPTSTR msg = NULL;

    if (!FormatMessage(flags, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&msg, 0, NULL))
    {
        WriteStdErr(TEXT("Error: %u\n"), code);
        return FALSE;
    }

    BOOL ret = WriteStdErr(TEXT("%u: %s"), code, msg);

    LocalFree(msg);

    return ret;
}

// -----------------------------------------------------------------------------------------------

BOOL WriteOutputA(DWORD fd, LPCSTR format, va_list args)
{
    CHAR msg[BUF_SIZE] = {0};

    HRESULT ret = StringCbVPrintfA(msg, BUF_SIZE * sizeof(CHAR), format, args);
    if (FAILED(ret))
    {
        WriteStdErr(TEXT("Error: %u\n"), ret);
        return FALSE;
    }

    HANDLE handle = GetStdHandle(fd);
    DWORD written = 0;
    return WriteFile(handle, msg, lstrlenA(msg) * sizeof(CHAR), &written, NULL);
}

BOOL WriteOutputW(DWORD fd, LPCWSTR format, va_list args)
{
    WCHAR msg[BUF_SIZE] = {0};

    HRESULT ret = StringCbVPrintfW(msg, BUF_SIZE * sizeof(WCHAR), format, args);
    if (FAILED(ret))
    {
        WriteStdErr(TEXT("Error: %u\n"), ret);
        return FALSE;
    }

    LPSTR msgA = NULL;
    if (!WideToMB(GetProcessHeap(), msg, &msgA))
    {
        WriteLastSystemError();
        return FALSE;
    }

    HANDLE handle = GetStdHandle(fd);
    DWORD written = 0;
    BOOL retA = WriteFile(handle, msgA, lstrlenA(msgA) * sizeof(CHAR), &written, NULL);
    HeapFree(GetProcessHeap(), 0, msgA);

    return retA;
}
