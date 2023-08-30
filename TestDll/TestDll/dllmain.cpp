
#include <Windows.h>
#include <stdio.h>
#pragma warning(disable:4996)


DWORD callback(LPVOID lpThreadParameter)
{
    int i = 10;
    char buf[32] = { 0 };
    while (i)
    {
        sprintf(buf, "dll: index:%d", i);
        OutputDebugStringA(buf);
        i--;
        Sleep(1000);
    }

    OutputDebugStringA("dll:thread exit...");
    return 0;
}

HANDLE hThread = NULL;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("dll:DLL_PROCESS_ATTACH");
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)callback, NULL, 0, 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        OutputDebugStringA("dll:DLL_PROCESS_DETACH");
        break;
    }
    return TRUE;
}

