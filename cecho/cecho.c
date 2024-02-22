#pragma warning(disable : 4464)
#pragma warning(once : 4710)
#pragma warning(once : 4711)
#pragma warning(disable : 5045)

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "../common/console.h"

#ifdef UNICODE
int wmain(int argc, TCHAR *argv[])
#else
int main(int argc, TCHAR *argv[])
#endif
{
    BOOL escape = TRUE;
    BOOL newline = TRUE;

    LPTSTR *arg = NULL;
    for (arg = argv + 1; (arg - argv) < argc; arg += 1)
    {
        if (!lstrcmp(*arg, TEXT("-e")))
        {
            escape = FALSE;
        }
        else if (!lstrcmp(*arg, TEXT("-E")))
        {
            escape = TRUE;
        }
        else if (!lstrcmp(*arg, TEXT("-n")))
        {
            newline = FALSE;
        }
        else
        {
            break;
        }
    }

    for (; (arg - argv) < argc; arg += 1)
    {
        if (escape)
        {
            WriteStdOut(TEXT("%s"), *arg);
        }
        else
        {
            int len = lstrlen(*arg);
            for (int i = 0; i < len; i++)
            {
                TCHAR cur = (*arg)[i];
                if (cur != '\\' || i + 1 == len)
                {
                    WriteStdOut(TEXT("%c"), cur);
                }
                else
                {
                    i += 1;
                    TCHAR next = (*arg)[i];
                    switch (next)
                    {
                    case '\\':
                        WriteStdOut(TEXT("\\"));
                        break;
                    case 'a':
                        WriteStdOut(TEXT("\a"));
                        break;
                    case 'b':
                        WriteStdOut(TEXT("\b"));
                        break;
                    case 'f':
                        WriteStdOut(TEXT("\f"));
                        break;
                    case 'n':
                        WriteStdOut(TEXT("\n"));
                        break;
                    case 'r':
                        WriteStdOut(TEXT("\r"));
                        break;
                    case 't':
                        WriteStdOut(TEXT("\t"));
                        break;
                    case 'v':
                        WriteStdOut(TEXT("\v"));
                        break;
                    default:
                        WriteStdOut(TEXT("\\%c"), next);
                        break;
                    }
                }
            }
        }

        if ((arg - argv) < (argc - 1))
        {
            WriteStdOut(TEXT(" "));
        }
    }

    if (newline)
    {
        WriteStdOut(TEXT("\r\n"));
    }
}
