#pragma comment(lib, "Bcrypt")

#pragma warning(disable : 4464)
#pragma warning(once : 4711)
#pragma warning(disable : 5045)

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>
#include "../common/console.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

BYTE IV[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

int Decode(LPTSTR, LPTSTR, LPTSTR);
int Encode(LPTSTR, LPTSTR, LPTSTR);
int GenKey(LPTSTR, LPTSTR);
int ShowInfo(void);
int ReadKey(LPTSTR, BCRYPT_KEY_HANDLE *);
int GetAes256Cbc(BCRYPT_ALG_HANDLE *);
int GetBlockSize(BCRYPT_ALG_HANDLE, DWORD *);

#ifdef UNICODE
int wmain(int argc, TCHAR *argv[])
#else
int main(int argc, TCHAR *argv[])
#endif
{
    BOOL decode = FALSE;
    BOOL genKey = FALSE;
    BOOL info = FALSE;
    LPTSTR password = NULL;
    LPTSTR keyPath = NULL;
    LPTSTR inputPath = NULL;
    LPTSTR outputPath = NULL;

    LPTSTR *arg = NULL;
    for (arg = argv + 1; (arg - argv) < argc; arg += 1)
    {
        if (*arg[0] != '-')
        {
            break;
        }
        else if (!lstrcmp(*arg, TEXT("-d")))
        {
            decode = TRUE;
        }
        else if (!lstrcmp(*arg, TEXT("-g")))
        {
            genKey = TRUE;
        }
        else if (!lstrcmp(*arg, TEXT("-v")))
        {
            info = TRUE;
        }
        else if (!lstrcmp(*arg, TEXT("-k")))
        {
            arg += 1;
            keyPath = *arg;
        }
        else if (!lstrcmp(*arg, TEXT("-p")))
        {
            arg += 1;
            password = *arg;
        }
        else
        {
            WriteStdErr(TEXT("Error: unknown option '%s'\n"), *arg);
            return 1;
        }
    }

    if (info)
    {
        return ShowInfo();
    }

    if (!genKey && (arg - argv) < argc && arg != NULL)
    {
        inputPath = *arg;
        arg += 1;
    }

    if ((arg - argv) < argc && arg != NULL)
    {
        outputPath = *arg;
        arg += 1;
    }

    if (genKey)
    {
        if (password == NULL)
        {
            WriteStdErr(TEXT("Error: missing -p option\n"));
            return 1;
        }

        return GenKey(password, outputPath);
    }

    if (keyPath == NULL)
    {
        WriteStdErr(TEXT("Error: missing -k option\n"));
        return 1;
    }

    return decode ? Decode(keyPath, inputPath, outputPath) : Encode(keyPath, inputPath, outputPath);
}

int Decode(LPTSTR keyPath, LPTSTR inputPath, LPTSTR outputPath)
{
    NTSTATUS status = -1;
    BCRYPT_ALG_HANDLE alg = NULL;
    HANDLE heap = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    HANDLE inputFp = INVALID_HANDLE_VALUE;
    BYTE *input = NULL;
    BYTE *output = NULL;
    HANDLE outputFp = INVALID_HANDLE_VALUE;

    status = GetAes256Cbc(&alg);
    if (!NT_SUCCESS(status))
    {
        goto END;
    }

    status = ReadKey(keyPath, &key);
    if (!NT_SUCCESS(status))
    {
        goto END;
    }

    heap = HeapCreate(0, 0, 0);

    status = -1;
    inputFp = CreateFile(inputPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (inputFp == INVALID_HANDLE_VALUE)
    {
        WriteLastSystemError();
        goto END;
    }

    DWORD inputSize = GetFileSize(inputFp, NULL);
    if (inputSize == INVALID_FILE_SIZE)
    {
        WriteLastSystemError();
        goto END;
    }

    input = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, inputSize * sizeof(BYTE));
    DWORD readInputSize = 0;
    if (!ReadFile(inputFp, input, inputSize, &readInputSize, NULL))
    {
        WriteLastSystemError();
        goto END;
    }

    DWORD ivSize = 0;
    status = GetBlockSize(alg, &ivSize);
    if (!NT_SUCCESS(status) || ivSize != sizeof(IV))
    {
        WriteStdErr(TEXT("Error: Can not acquire block size. (0x%08X)\n"), status);
        goto END;
    }

    DWORD outputSize = 0;
    status =
        BCryptDecrypt(key, input, inputSize, NULL, (PUCHAR)&IV, ivSize, NULL, 0, &outputSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not calculate plain text length. (0x%08X)\n"), status);
        goto END;
    }

    output = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, outputSize * sizeof(BYTE));
    DWORD readOutputSize = 0;
    status = BCryptDecrypt(key, input, inputSize, NULL, (PUCHAR)&IV, ivSize, output, outputSize, &readOutputSize,
                           BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not plain text. (0x%08X)\n"), status);
        goto END;
    }

    status = -1;
    outputFp = CreateFile(outputPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outputFp == INVALID_HANDLE_VALUE)
    {
        WriteLastSystemError();
        goto END;
    }

    DWORD written = 0;
    if (!WriteFile(outputFp, output, readOutputSize, &written, NULL))
    {
        WriteLastSystemError();
        goto END;
    }

    status = 0;
END:
    if (outputFp != INVALID_HANDLE_VALUE)
    {
        CloseHandle(outputFp);
    }

    if (output != NULL)
    {
        HeapFree(heap, 0, output);
    }

    if (input != NULL)
    {
        HeapFree(heap, 0, input);
    }

    if (inputFp != INVALID_HANDLE_VALUE)
    {
        CloseHandle(inputFp);
    }

    if (key != NULL)
    {
        BCryptDestroyKey(key);
    }

    if (heap != NULL)
    {
        HeapDestroy(heap);
    }

    if (alg != NULL)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    return status;
}

int Encode(LPTSTR keyPath, LPTSTR inputPath, LPTSTR outputPath)
{
    NTSTATUS status = -1;
    BCRYPT_ALG_HANDLE alg = NULL;
    HANDLE heap = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    HANDLE inputFp = INVALID_HANDLE_VALUE;
    BYTE *input = NULL;
    BYTE *output = NULL;
    HANDLE outputFp = INVALID_HANDLE_VALUE;

    status = GetAes256Cbc(&alg);
    if (!NT_SUCCESS(status))
    {
        goto END;
    }

    status = ReadKey(keyPath, &key);
    if (!NT_SUCCESS(status))
    {
        goto END;
    }

    heap = HeapCreate(0, 0, 0);

    status = -1;
    inputFp = CreateFile(inputPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (inputFp == INVALID_HANDLE_VALUE)
    {
        WriteLastSystemError();
        goto END;
    }

    DWORD inputSize = GetFileSize(inputFp, NULL);
    if (inputSize == INVALID_FILE_SIZE)
    {
        WriteLastSystemError();
        goto END;
    }

    input = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, inputSize * sizeof(BYTE));
    DWORD readInputSize = 0;
    if (!ReadFile(inputFp, input, inputSize, &readInputSize, NULL))
    {
        WriteLastSystemError();
        goto END;
    }

    DWORD ivSize = 0;
    status = GetBlockSize(alg, &ivSize);
    if (!NT_SUCCESS(status) || ivSize != sizeof(IV))
    {
        WriteStdErr(TEXT("Error: Can not acquire block size. (0x%08X)\n"), status);
        goto END;
    }

    DWORD outputSize = 0;
    status =
        BCryptEncrypt(key, input, inputSize, NULL, (PUCHAR)&IV, ivSize, NULL, 0, &outputSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not calculate cipher text length. (0x%08X)\n"), status);
        goto END;
    }

    output = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, outputSize * sizeof(BYTE));
    DWORD readOutputSize = 0;
    status = BCryptEncrypt(key, input, inputSize, NULL, (PUCHAR)&IV, ivSize, output, outputSize, &readOutputSize,
                           BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not cipher text. (0x%08X)\n"), status);
        goto END;
    }

    status = -1;
    outputFp = CreateFile(outputPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outputFp == INVALID_HANDLE_VALUE)
    {
        WriteLastSystemError();
        goto END;
    }

    DWORD written = 0;
    if (!WriteFile(outputFp, output, outputSize, &written, NULL))
    {
        WriteLastSystemError();
        goto END;
    }

    status = 0;
END:
    if (outputFp != INVALID_HANDLE_VALUE)
    {
        CloseHandle(outputFp);
    }

    if (output != NULL)
    {
        HeapFree(heap, 0, output);
    }

    if (input != NULL)
    {
        HeapFree(heap, 0, input);
    }

    if (inputFp != INVALID_HANDLE_VALUE)
    {
        CloseHandle(inputFp);
    }

    if (key != NULL)
    {
        BCryptDestroyKey(key);
    }

    if (heap != NULL)
    {
        HeapDestroy(heap);
    }

    if (alg != NULL)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    return status;
}

int GenKey(LPTSTR password, LPTSTR outputPath)
{
    NTSTATUS status = -1;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    HANDLE heap = NULL;
    BYTE *output = NULL;
    HANDLE fp = INVALID_HANDLE_VALUE;

    status = GetAes256Cbc(&alg);
    if (!NT_SUCCESS(status))
    {
        goto END;
    }

    status = BCryptGenerateSymmetricKey(alg, &key, NULL, 0, (PUCHAR)password, lstrlen(password) * sizeof(TCHAR), 0);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not generate key. (0x%08X)\n"), status);
        goto END;
    }

    ULONG length = 0;
    status = BCryptExportKey(key, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 0, &length, 0);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not acquire export size. (0x%08X)\n"), status);
        goto END;
    }

    heap = HeapCreate(0, 0, 0);
    output = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, length * sizeof(BYTE));

    status = BCryptExportKey(key, NULL, BCRYPT_KEY_DATA_BLOB, output, length, &length, 0);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not export key. (0x%08X)\n"), status);
        goto END;
    }

    status = -1;
    // Key Data Blob Magic(12 Bytes) + password (32 Bytes)
    fp = CreateFile(outputPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fp == INVALID_HANDLE_VALUE)
    {
        WriteLastSystemError();
        goto END;
    }

    DWORD written = 0;
    if (!WriteFile(fp, output, length * sizeof(BYTE), &written, NULL))
    {
        WriteLastSystemError();
        goto END;
    }

    status = 0;
END:
    if (fp != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fp);
    }

    if (output != NULL)
    {
        HeapFree(heap, 0, output);
    }

    if (heap != NULL)
    {
        HeapDestroy(heap);
    }

    if (key != NULL)
    {
        BCryptDestroyKey(key);
    }

    if (alg != NULL)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    return status;
}

int ShowInfo(void)
{
    NTSTATUS status = -1;
    BCRYPT_ALG_HANDLE alg = NULL;
    DWORD length = 0;

    status = GetAes256Cbc(&alg);
    if (!NT_SUCCESS(status))
    {
        goto END;
    }

    // BCRYPT_BLOCK_LENGTH
    DWORD blockSize = 0;
    status = GetBlockSize(alg, &blockSize);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not acquire block size. (0x%08X)\n"), status);
        goto END;
    }

    WriteStdOut(TEXT("Block Size\t: %d\n"), blockSize);

    // BCRYPT_KEY_LENGTH
    /*
    DWORD keySize = 0;
    status = BCryptGetProperty(alg, BCRYPT_KEY_LENGTH, (PUCHAR)&keySize, sizeof(DWORD), &length, 0);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not acquire key size. (0x%08X)\n"), status);
        goto END;
    }

    WriteStdOut(TEXT("Key Size\t: %d\n"), keySize);
    */

    // BCRYPT_KEY_LENGTHS
    BCRYPT_KEY_LENGTHS_STRUCT keys = {0};
    status = BCryptGetProperty(alg, BCRYPT_KEY_LENGTHS, (PUCHAR)&keys, sizeof(BCRYPT_KEY_LENGTHS_STRUCT), &length, 0);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not acquire supported key size. (0x%08X)\n"), status);
        goto END;
    }

    WriteStdOut(TEXT("Supported Key Size\t: %d-%d (+%d)\n"), keys.dwMinLength, keys.dwMaxLength, keys.dwIncrement);

    status = 0;
END:
    if (alg != NULL)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    return status;
}

int ReadKey(LPTSTR keyPath, BCRYPT_KEY_HANDLE *key)
{
    NTSTATUS status = -1;
    BCRYPT_ALG_HANDLE alg = NULL;
    HANDLE heap = NULL;
    HANDLE fp = INVALID_HANDLE_VALUE;
    BYTE *keyBlob = NULL;

    status = GetAes256Cbc(&alg);
    if (!NT_SUCCESS(status))
    {
        goto END;
    }

    heap = HeapCreate(0, 0, 0);

    status = -1;
    fp = CreateFile(keyPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fp == INVALID_HANDLE_VALUE)
    {
        WriteLastSystemError();
        goto END;
    }

    DWORD keySize = GetFileSize(fp, NULL);
    if (keySize == INVALID_FILE_SIZE)
    {
        WriteLastSystemError();
        goto END;
    }

    keyBlob = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, keySize * sizeof(BYTE));
    DWORD readKeySize = 0;
    if (!ReadFile(fp, keyBlob, keySize, &readKeySize, NULL))
    {
        WriteLastSystemError();
        goto END;
    }

    status = BCryptImportKey(alg, NULL, BCRYPT_KEY_DATA_BLOB, key, NULL, 0, keyBlob, keySize, 0);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not import key. (0x%08X)\n"), status);
        goto END;
    }

END:
    if (keyBlob != NULL)
    {
        HeapFree(heap, 0, keyBlob);
    }

    if (fp != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fp);
    }

    if (heap != NULL)
    {
        HeapDestroy(heap);
    }

    if (alg != NULL)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    return status;
}

int GetAes256Cbc(BCRYPT_ALG_HANDLE *alg)
{
    NTSTATUS status = -1;

    status = BCryptOpenAlgorithmProvider(alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Not found algorithm provider. (0x%08X)\n"), status);
        return status;
    }

    status =
        BCryptSetProperty(*alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status))
    {
        WriteStdErr(TEXT("Error: Can not configure block mode. (0x%08X)\n"), status);
        return status;
    }

    return status;
}

int GetBlockSize(BCRYPT_ALG_HANDLE alg, DWORD *blockSize)
{
    DWORD length = 0;
    return BCryptGetProperty(alg, BCRYPT_BLOCK_LENGTH, (PUCHAR)blockSize, sizeof(DWORD), &length, 0);
}
