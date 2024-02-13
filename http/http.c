#pragma comment(lib, "Winhttp")

#pragma warning(once : 4710)
#pragma warning(once : 4711)

#include <windows.h>
#include <winhttp.h>
#include "../common/console.h"
#include "../common/string.h"

int Get(HANDLE, LPCTSTR);

#define METHOD_NONE 0
#define METHOD_GET 1

#ifdef UNICODE
int wmain(int argc, TCHAR *argv[])
#else
int main(int argc, TCHAR *argv[])
#endif
{
    LPTSTR url = NULL;
    int method = METHOD_NONE;

    LPTSTR *arg = NULL;
    for (arg = argv + 1; (arg - argv) < argc; arg += 1)
    {
        if (*arg[0] != '-')
        {
            if (url != NULL)
            {
                WriteStdErr(TEXT("Error: can not specify URL twice and more '%s'\n"), *arg);
                return 1;
            }

            url = *arg;
        }
        else if (!lstrcmp(*arg, TEXT("-X")))
        {
            if (method != METHOD_NONE)
            {
                WriteStdErr(TEXT("Error: can not specify HTTP method twice and more '%s'\n"), *arg);
                return 1;
            }

            arg += 1;
            if (!lstrcmpi(*arg, TEXT("GET")))
            {
                method = METHOD_GET;
            }
            else
            {
                WriteStdErr(TEXT("Error: unknown HTTP method '%s'\n"), *arg);
                return 1;
            }
        }
        else
        {
            WriteStdErr(TEXT("Error: unknown option '%s'\n"), *arg);
            return 1;
        }
    }

    int exitCode = 0;

    HANDLE heap = HeapCreate(0, 0, 0);

    switch (method)
    {
    case METHOD_NONE:
    case METHOD_GET:
        exitCode = Get(heap, url);
        break;
    }

    HeapDestroy(heap);

    return exitCode;
}

int Get(HANDLE heap, LPCTSTR urlString)
{
    int exitCode = 0;
    LPWSTR wUrlString = NULL;
    URL_COMPONENTS url = {0};
    LPWSTR hostName = NULL;
    LPWSTR urlPath = NULL;
    HINTERNET session = NULL;
    HINTERNET connect = NULL;
    HINTERNET request = NULL;

#ifdef UNICODE
    wUrlString = (LPWSTR)urlString;
#else
    if (!MBToWide(heap, urlString, &wUrlString))
    {
        WriteLastSystemError();
        exitCode = -1;
        goto END;
    }
#endif

    url.dwStructSize = sizeof(URL_COMPONENTS);
    url.dwSchemeLength = (DWORD)-1;
    url.dwHostNameLength = (DWORD)-1;
    url.dwUserNameLength = (DWORD)-1;
    url.dwPasswordLength = (DWORD)-1;
    url.dwUrlPathLength = (DWORD)-1;
    url.dwExtraInfoLength = (DWORD)-1;
    if (!WinHttpCrackUrl(wUrlString, 0, 0, &url))
    {
        WriteLastSystemError();
        exitCode = -2;
        goto END;
    }

    if (!SubStringW(heap, url.lpszHostName, url.dwHostNameLength, &hostName))
    {
        exitCode = -2;
        goto END;
    }

    if (!SubStringW(heap, url.lpszUrlPath, url.dwUrlPathLength, &urlPath))
    {
        exitCode = -2;
        goto END;
    }

    session = WinHttpOpen(L"WinHTTP Client/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS, 0);
    if (NULL == session)
    {
        WriteLastSystemError();
        exitCode = -3;
        goto END;
    }

    connect = WinHttpConnect(session, hostName, url.nPort, 0);
    if (NULL == connect)
    {
        WriteLastSystemError();
        exitCode = -4;
        goto END;
    }

    request = WinHttpOpenRequest(connect, L"GET", urlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (NULL == request)
    {
        WriteLastSystemError();
        exitCode = -5;
        goto END;
    }

    if (!WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, 0))
    {
        WriteLastSystemError();
        exitCode = -6;
        goto END;
    }

    if (!WinHttpReceiveResponse(request, NULL))
    {
        WriteLastSystemError();
        exitCode = -7;
        goto END;
    }

    DWORD received = 0;
    do
    {
        received = 0;
        if (!WinHttpQueryDataAvailable(request, &received))
        {
            WriteLastSystemError();
            exitCode = -8;
            goto END;
        }

        if (received > 0)
        {
            PBYTE data = (PBYTE)HeapAlloc(heap, HEAP_ZERO_MEMORY, (received + 1) * sizeof(BYTE));
            if (NULL == data)
            {
                WriteLastSystemError();
                exitCode = -9;
                goto END;
            }

            DWORD readed = 0;
            if (!WinHttpReadData(request, data, received, &readed))
            {
                WriteLastSystemError();
                exitCode = -10;
                HeapFree(heap, 0, data);
                goto END;
            }

            WriteStdOutA("%s", data);

            HeapFree(heap, 0, data);
        }
    } while (received > 0);

    WriteStdOutA("\n");

END:
    if (NULL != request)
    {
        WinHttpCloseHandle(request);
    }

    if (NULL != connect)
    {
        WinHttpCloseHandle(connect);
    }

    if (NULL != session)
    {
        WinHttpCloseHandle(session);
    }

    if (NULL != hostName)
    {
        HeapFree(heap, 0, hostName);
    }

    if (NULL != urlPath)
    {
        HeapFree(heap, 0, urlPath);
    }

#ifndef UNICODE
    if (NULL != wUrlString)
    {
        HeapFree(heap, 0, wUrlString);
    }
#endif

    return exitCode;
}
