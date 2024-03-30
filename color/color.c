#pragma comment(lib, "Shlwapi")

#pragma warning(disable : 4464)

#define WIN32_LEAN_AND_MEAN

#include "../common/console.h"
#include <shlwapi.h>
#include <windows.h>

#ifdef UNICODE
int wmain(int argc, TCHAR *argv[])
#else
int main(int argc, TCHAR *argv[])
#endif
{
    int index = -1;

    if (argc != 2)
    {
        WriteStdErr(TEXT("Error: not specify index\n"));
        return 1;
    }

    if (!StrToIntEx(argv[1], STIF_DEFAULT, &index) || index < 0 || 15 < index)
    {
        WriteStdErr(TEXT("Error: invalid value '%s'\n"), argv[1]);
        return 2;
    }

    CONSOLE_SCREEN_BUFFER_INFOEX info;
    info.cbSize = sizeof(CONSOLE_SCREEN_BUFFER_INFOEX);

    HANDLE stdout = GetStdHandle(STD_OUTPUT_HANDLE);

    if (!GetConsoleScreenBufferInfoEx(stdout, &info))
    {
        WriteLastSystemError();
        return -1;
    }

    // list color table in property of command prompt.
    for (int i = 0; i < sizeof(info.ColorTable) / sizeof(COLORREF); i++)
    {
        COLORREF color = info.ColorTable[i];
        BYTE red = GetRValue(color);
        BYTE green = GetGValue(color);
        BYTE blue = GetBValue(color);

        WriteStdOut(TEXT("[%2d] #%02X%02X%02X\n"), i, red, green, blue);
    }

    WriteStdOut(TEXT("\n"));

    // Output coloring string.
    if (!SetConsoleTextAttribute(stdout, (WORD)index))
    {
        WriteLastSystemError();
        return -2;
    }

    WriteStdOut(TEXT("Hello, World!\n"));

    if (!SetConsoleTextAttribute(stdout, info.wAttributes))
    {
        WriteLastSystemError();
        return -3;
    }
}
