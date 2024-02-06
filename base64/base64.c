#pragma comment(lib, "Crypt32")
#pragma comment(lib, "Shlwapi")

#pragma warning(once : 4710)
#pragma warning(once : 4711)

#include <fcntl.h>
#include <io.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string.h>
#include <wincrypt.h>
#include <windows.h>

int DecodeB64(char *);
int DecodeString(char *, size_t, unsigned char **, size_t *);
int EncodeB64(char *, int);
int EncodeString(unsigned char *, size_t, char **, size_t *);
int GetFileContent(FILE *, unsigned char **, size_t *);
int RemoveLF(unsigned char *, size_t *);
int WrapWrite(unsigned char *, size_t, int);

int main(int argc, char *argv[])
{
    BOOL decode = FALSE;
    int width = 76;
    char *filePath = NULL;

    char **arg = NULL;
    for (arg = argv + 1; arg - argv < argc; arg += 1)
    {
        if (*arg[0] != '-')
        {
            break;
        }
        else if (!strcmp(*arg, "-d"))
        {
            decode = TRUE;
        }
        else if (!strcmp(*arg, "-w"))
        {
            arg += 1;
            if (!StrToIntExA(*arg, STIF_DEFAULT, &width) || width < 0)
            {
                fprintf(stderr, "Error: invalid value -w '%s'\n", *arg);
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "Error: unknown option '%s'\n", *arg);
            return 1;
        }
    }

    if (arg != NULL)
    {
        filePath = *arg;
    }

    return decode ? DecodeB64(filePath) : EncodeB64(filePath, width);
}

int DecodeB64(char *filePath)
{
    int exitCode = 0;
    FILE *fp = stdin;
    unsigned char *content = NULL;
    unsigned char *decoded = NULL;

    if (filePath == NULL)
    {
        _setmode(_fileno(stdin), _O_BINARY);
    }
    else
    {
        fp = fopen(filePath, "rb");
        if (fp == NULL)
        {
            fprintf(stderr, "%s: %s\n", strerror(errno), filePath);
            exitCode = 2;
            goto END;
        }
    }

    size_t fileLength = 0;
    if (GetFileContent(fp, &content, &fileLength))
    {
        fprintf(stderr, "%s: %s\n", strerror(errno), filePath);
        exitCode = 3;
        goto END;
    }

    RemoveLF(content, &fileLength);

    size_t decodedLength = 0;
    if (DecodeString((char *)content, fileLength, &decoded, &decodedLength))
    {
        fprintf(stderr, "Error: decode '%s' (%lu)\n", content, GetLastError());
        exitCode = 4;
        goto END;
    }

    _setmode(_fileno(stdout), _O_BINARY);
    if (!fwrite(decoded, sizeof(unsigned char), decodedLength, stdout))
    {
        fprintf(stderr, "%s: %s\n", strerror(errno), "stdout");
        exitCode = 5;
        goto END;
    }

    goto END;

END:
    if (decoded != NULL)
    {
        free(decoded);
    }

    if (content != NULL)
    {
        free(content);
    }

    if (fp != NULL && fp != stdin)
    {
        fclose(fp);
    }

    return exitCode;
}

int EncodeB64(char *filePath, int width)
{
    int exitCode = 0;
    FILE *fp = stdin;
    unsigned char *content = NULL;
    unsigned char *encoded = NULL;

    if (filePath == NULL)
    {
        _setmode(_fileno(stdin), _O_BINARY);
    }
    else
    {
        fp = fopen(filePath, "rb");
        if (fp == NULL)
        {
            fprintf(stderr, "%s: %s\n", strerror(errno), filePath);
            exitCode = 2;
            goto END;
        }
    }

    size_t fileLength = 0;
    if (GetFileContent(fp, &content, &fileLength))
    {
        fprintf(stderr, "%s: %s\n", strerror(errno), filePath);
        exitCode = 3;
        goto END;
    }

    size_t encodedLength = 0;
    if (EncodeString(content, fileLength, (char **)&encoded, &encodedLength))
    {
        fprintf(stderr, "Error: encode '%s' (%lu)\n", content, GetLastError());
        exitCode = 4;
        goto END;
    }

    _setmode(_fileno(stdout), _O_BINARY);
    if (WrapWrite(encoded, encodedLength, width))
    {
        fprintf(stderr, "%s: %s\n", strerror(errno), "stdout");
        exitCode = 5;
        goto END;
    }

    goto END;

END:
    if (encoded != NULL)
    {
        free(encoded);
    }

    if (content != NULL)
    {
        free(content);
    }

    if (fp != NULL && fp != stdin)
    {
        fclose(fp);
    }

    return exitCode;
}

int DecodeString(char *source, size_t sourceLength, unsigned char **decoded, size_t *decodedLenth)
{
    *decoded = NULL;

    DWORD flags = CRYPT_STRING_BASE64;

    *decodedLenth = 0;
    if (!CryptStringToBinaryA(source, (DWORD)sourceLength, flags, NULL, (DWORD *)decodedLenth, NULL, NULL))
    {
        return 1;
    }

    *decoded = (unsigned char *)calloc(*decodedLenth, sizeof(unsigned char));
    if (*decoded == NULL)
    {
        return 1;
    }

    if (!CryptStringToBinaryA(source, (DWORD)sourceLength, flags, *decoded, (DWORD *)decodedLenth, NULL, NULL))
    {
        free(*decoded);
        *decoded = NULL;
        return 1;
    }

    return 0;
}

int EncodeString(unsigned char *source, size_t sourceLength, char **encoded, size_t *encodedLength)
{
    *encoded = NULL;

    DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;

    *encodedLength = 0;
    if (!CryptBinaryToStringA(source, (DWORD)sourceLength, flags, NULL, (DWORD *)encodedLength))
    {
        return 1;
    }

    *encoded = (char *)calloc(*encodedLength, sizeof(char));
    if (*encoded == NULL)
    {
        return 1;
    }

    if (!CryptBinaryToStringA(source, (DWORD)sourceLength, flags, *encoded, (DWORD *)encodedLength))
    {
        free(*encoded);
        *encoded = NULL;
        return 1;
    }

    return 0;
}

int GetFileContent(FILE *fp, unsigned char **content, size_t *fileLength)
{
    *fileLength = 0;
    *content = (unsigned char *)calloc(1, sizeof(unsigned char)); // with null terminate.
    if (*content == NULL)
    {
        return 1;
    }

    size_t size = 0;
    unsigned char buffer[8192] = {0};
    while (size = fread(&buffer, sizeof(unsigned char), 8192, fp))
    {
        // realloc always return NULL ?
        unsigned char *tmp =
            (unsigned char *)calloc((*fileLength) + size + 1, sizeof(unsigned char)); // with null terminate.
        if (tmp == NULL)
        {
            free(*content);
            *content = NULL;
            return 1;
        }

        memmove(tmp, *content, *fileLength);
        memmove(tmp + *fileLength, &buffer, size);
        tmp[(*fileLength) + size] = '\0';

        free(*content);
        *content = tmp;

        (*fileLength) += size;

        memset(&buffer, 0, 8192);
    }

    return 0;
}

/*
// stdin is 8kiB buffering ?
// setvbuf does not be affected ?
int GetFileLength(FILE *fp, long *length)
{
    if (fseek(fp, 0, SEEK_END))
    {
        return 1;
    }

    *length = ftell(fp);
    if (*length < 0)
    {
        return 1;
    }

    if (fseek(fp, 0, SEEK_SET))
    {
        return 1;
    }

    return 0;
}
*/

int RemoveLF(unsigned char *content, size_t *contentLength)
{
    unsigned char *lf = NULL;

    while (lf = (unsigned char *)strchr((char *)content, '\n'))
    {
        unsigned char *next = lf + 1;
        size_t restLen = (*contentLength) - (next - content) + 1; // with null terminate.
        memmove(lf, next, restLen);
        (*contentLength)--;
    }

    return 0;
}

int WrapWrite(unsigned char *text, size_t textLength, int width)
{
    size_t chunk = width > 0 ? width : textLength;
    for (unsigned char *output = text; (size_t)(output - text) < textLength; output += chunk)
    {
        size_t len = strlen((char *)output);
        len = len < chunk ? len : chunk;

        if (!fwrite(output, sizeof(unsigned char), len, stdout))
        {
            return 1;
        }

        if (width > 0 && len == chunk)
        {
            // only '\n' char because of avoiding occurring error on Linux.
            if (!fwrite("\n", sizeof(unsigned char), 1, stdout))
            {
                return 1;
            }
        }
    }

    return 0;
}
