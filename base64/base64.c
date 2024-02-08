#pragma comment(lib, "Crypt32")
#pragma comment(lib, "Shell32")
#pragma comment(lib, "Shlwapi")

#pragma warning(once : 4710)
#pragma warning(once : 4711)

#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <wincrypt.h>

int DecodeB64(LPSTR);
BOOL DecodeString(HANDLE, LPCSTR, DWORD, BYTE **, DWORD *);
int EncodeB64(LPSTR, int);
BOOL EncodeString(HANDLE, BYTE *, DWORD, LPSTR *, DWORD *);
BOOL GetFileContent(HANDLE, HANDLE, BYTE **, SIZE_T *);
BOOL RemoveLF(BYTE *, SIZE_T *);
BOOL WrapWrite(BYTE *, DWORD, int);
void WriteStdErrorA(LPCSTR, ...);
void WriteLastError(void);

int main(int argc, char *argv[])
{
    BOOL decode = FALSE;
    int width = 76;
    LPSTR filePath = NULL;

    LPSTR *arg = NULL;
    for (arg = argv + 1; (arg - argv) < argc; arg += 1)
    {
        if (*arg[0] != '-')
        {
            break;
        }
        else if (!StrCmpA(*arg, "-d"))
        {
            decode = TRUE;
        }
        else if (!StrCmpA(*arg, "-w"))
        {
            arg += 1;
            if (!StrToIntExA(*arg, STIF_DEFAULT, &width) || width < 0)
            {
                WriteStdErrorA("Error: invalid value -w '%s'\n", *arg);
                return 1;
            }
        }
        else
        {
            WriteStdErrorA("Error: unknown option '%s'\n", *arg);
            return 1;
        }
    }

    if (arg != NULL)
    {
        filePath = *arg;
    }

    return decode ? DecodeB64(filePath) : EncodeB64(filePath, width);
}

int DecodeB64(LPSTR filePath)
{
    int exitCode = 0;
    HANDLE fp = GetStdHandle(STD_INPUT_HANDLE);
    BYTE *content = NULL;
    BYTE *decoded = NULL;

    if (filePath != NULL)
    {
        fp = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fp == INVALID_HANDLE_VALUE)
        {
            WriteLastError();
            exitCode = 2;
            goto END;
        }
    }

    HANDLE heap = HeapCreate(0, 0, 0);

    DWORD fileLength = 0;
    if (!GetFileContent(heap, fp, &content, (SIZE_T *)&fileLength))
    {
        WriteLastError();
        exitCode = 3;
        goto END;
    }

    RemoveLF(content, (SIZE_T *)&fileLength);

    DWORD decodedLength = 0;
    if (!DecodeString(heap, (LPCSTR)content, fileLength, &decoded, &decodedLength))
    {
        WriteLastError();
        exitCode = 4;
        goto END;
    }

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    if (!WriteFile(out, decoded, lstrlenA((LPCSTR)decoded) * sizeof(BYTE), &written, NULL))
    {
        WriteLastError();
        exitCode = 5;
        goto END;
    }

    goto END;

END:
    if (decoded != NULL)
    {
        HeapFree(heap, 0, decoded);
    }

    if (content != NULL)
    {
        HeapFree(heap, 0, content);
    }

    if (fp != INVALID_HANDLE_VALUE && filePath != NULL)
    {
        CloseHandle(fp);
    }

    HeapDestroy(heap);

    return exitCode;
}

int EncodeB64(LPSTR filePath, int width)
{
    int exitCode = 0;
    HANDLE fp = GetStdHandle(STD_INPUT_HANDLE);
    BYTE *content = NULL;
    BYTE *encoded = NULL;

    if (filePath != NULL)
    {
        fp = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fp == INVALID_HANDLE_VALUE)
        {
            WriteLastError();
            exitCode = 2;
            goto END;
        }
    }

    HANDLE heap = HeapCreate(0, 0, 0);

    SIZE_T fileLength = 0;
    if (!GetFileContent(heap, fp, &content, &fileLength))
    {
        WriteLastError();
        exitCode = 3;
        goto END;
    }

    DWORD encodedLength = 0;
    if (!EncodeString(heap, content, (DWORD)fileLength, (LPSTR *)&encoded, &encodedLength))
    {
        WriteLastError();
        exitCode = 4;
        goto END;
    }

    if (!WrapWrite(encoded, encodedLength, width))
    {
        WriteLastError();
        exitCode = 5;
        goto END;
    }

    goto END;

END:
    if (encoded != NULL)
    {
        HeapFree(heap, 0, encoded);
    }

    if (content != NULL)
    {
        HeapFree(heap, 0, content);
    }

    if (fp != INVALID_HANDLE_VALUE && filePath != NULL)
    {
        CloseHandle(fp);
    }

    HeapDestroy(heap);

    return exitCode;
}

BOOL DecodeString(HANDLE heap, LPCSTR source, DWORD sourceLength, BYTE **decoded, DWORD *decodedLenth)
{
    *decoded = NULL;

    DWORD flags = CRYPT_STRING_BASE64;

    *decodedLenth = 0;
    if (!CryptStringToBinaryA(source, sourceLength, flags, NULL, decodedLenth, NULL, NULL))
    {
        return FALSE;
    }

    *decoded = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, (*decodedLenth) * sizeof(BYTE));
    if (*decoded == NULL)
    {
        return FALSE;
    }

    if (!CryptStringToBinaryA(source, sourceLength, flags, *decoded, decodedLenth, NULL, NULL))
    {
        HeapFree(heap, 0, *decoded);
        *decoded = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL EncodeString(HANDLE heap, BYTE *source, DWORD sourceLength, LPSTR *encoded, DWORD *encodedLength)
{
    *encoded = NULL;

    DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;

    *encodedLength = 0;
    if (!CryptBinaryToStringA(source, sourceLength, flags, NULL, encodedLength))
    {
        return FALSE;
    }

    *encoded = (LPSTR)HeapAlloc(heap, HEAP_ZERO_MEMORY, (*encodedLength) * sizeof(CHAR));
    if (*encoded == NULL)
    {
        return FALSE;
    }

    if (!CryptBinaryToStringA(source, sourceLength, flags, *encoded, encodedLength))
    {
        HeapFree(heap, 0, *encoded);
        *encoded = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL GetFileContent(HANDLE heap, HANDLE fp, BYTE **content, SIZE_T *fileLength)
{
    *fileLength = 0;
    *content = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(BYTE)); // with null terminate.
    if (*content == NULL)
    {
        return FALSE;
    }

    DWORD size = 0;
    BYTE buffer[8192] = {0};
    while (ReadFile(fp, &buffer, 8192 * sizeof(BYTE), &size, NULL))
    {
        if (size <= 0)
        {
            break;
        }

        SIZE_T count = (*fileLength) + size + 1; // with null terminate.
        BYTE *tmp = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, count * sizeof(BYTE));
        if (tmp == NULL)
        {
            HeapFree(heap, 0, *content);
            *content = NULL;
            return FALSE;
        }

        MoveMemory(tmp, *content, (*fileLength) * sizeof(BYTE));
        MoveMemory(tmp + *fileLength, &buffer, size * sizeof(BYTE));
        tmp[(*fileLength) + size] = '\0';

        HeapFree(heap, 0, *content);
        *content = tmp;

        (*fileLength) += size;

        ZeroMemory(&buffer, 8192 * sizeof(BYTE));
    }

    return TRUE;
}

BOOL RemoveLF(BYTE *content, SIZE_T *contentLength)
{
    BYTE *lf = NULL;

    while (lf = (BYTE *)StrChrA((PCSTR)content, '\n'))
    {
        BYTE *next = lf + 1;
        SIZE_T restLen = (*contentLength) - (next - content) + sizeof(BYTE); // with null terminate.
        MoveMemory(lf, next, restLen);
        (*contentLength)--;
    }

    return TRUE;
}

BOOL WrapWrite(BYTE *text, DWORD textLength, int width)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);

    DWORD chunk = width > 0 ? width : textLength;
    DWORD written = 0;
    for (BYTE *output = text; (DWORD)(output - text) < textLength; output += chunk)
    {
        DWORD len = lstrlenA((LPCSTR)output);
        len = len < chunk ? len : chunk;

        if (!WriteFile(out, output, len * sizeof(BYTE), &written, NULL))
        {
            return FALSE;
        }

        if (width > 0 && len == chunk)
        {
            // only '\n' char because of avoiding occurring error on Linux.
            if (!WriteFile(out, "\n", sizeof(BYTE), &written, NULL))
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}

void WriteStdErrorA(LPCSTR format, ...)
{
    CHAR msg[1024] = {0};

    va_list args = NULL;
    va_start(args, format);

    HRESULT ret = StringCbVPrintfA(msg, 1024, format, args);
    if (FAILED(ret))
    {
        va_end(args);
        return;
    }

    va_end(args);

    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    WriteFile(err, msg, lstrlenA(msg) * sizeof(CHAR), &written, NULL);
}

void WriteLastError(void)
{
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD code = GetLastError();
    LPTSTR msg = NULL;

    if (!FormatMessage(flags, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&msg, 0, NULL))
    {
        return;
    }

    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    WriteFile(err, msg, lstrlen(msg) * sizeof(TCHAR), &written, NULL);

    LocalFree(msg);
}
