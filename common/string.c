#pragma warning(once : 4710)
#pragma warning(once : 4711)

#include <windows.h>
#include <strsafe.h>
#include "string.h"

BOOL WideToMB(HANDLE heap, LPCWSTR input, LPSTR *output)
{
    int len = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, (LPCWCH)input, -1, NULL, 0, NULL, NULL);
    if (len == 0)
    {
        return FALSE;
    }

    *output = (LPSTR)HeapAlloc(heap, HEAP_ZERO_MEMORY, len * sizeof(CHAR));
    if (*output == NULL)
    {
        return FALSE;
    }

    len = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, (LPCWCH)input, -1, *output, len, NULL, NULL);
    if (len == 0)
    {
        HeapFree(heap, 0, *output);
        *output = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL MBToWide(HANDLE heap, LPCSTR input, LPWSTR *output)
{
    int len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)input, -1, NULL, 0);
    if (len == 0)
    {
        return FALSE;
    }

    *output = (LPWSTR)HeapAlloc(heap, HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
    if (*output == NULL)
    {
        return FALSE;
    }

    len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)input, -1, *output, len);
    if (len == 0)
    {
        HeapFree(heap, 0, *output);
        *output = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL SubStringW(HANDLE heap, LPCWSTR value, DWORD count, LPWSTR *substring)
{
    *substring = (LPWSTR)HeapAlloc(heap, HEAP_ZERO_MEMORY, (count + 1) * sizeof(WCHAR));
    if (*substring == NULL)
    {
        return FALSE;
    }

    HRESULT ret = StringCchCopyNW(*substring, count + 1, value, count);
    if (FAILED(ret))
    {
        HeapFree(heap, 0, *substring);
        *substring = NULL;
        return FALSE;
    }

    return TRUE;
}
