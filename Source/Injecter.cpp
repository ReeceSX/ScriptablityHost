/*
    Purpose:
    Author: J. Reece Wilson
    License: All rights reserved (2019)
*/
#include "Injecter.hpp"
#include <Windows.h>
#include <string>

// Kernel32.dll is always at the same address... So much for ROP prevention guys...
static const size_t LoadLibraryConstantAddress = (size_t)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");

static const char * GetPath()
{
    static char pathCache[MAX_PATH] = { 0 };

    if (pathCache[0] != '\x00')
        return pathCache;

    GetModuleFileNameA(NULL, pathCache, MAX_PATH);

    for (int i = strnlen(pathCache, MAX_PATH); i; i--)
    {
        if (pathCache[i] == '\\')
        {
            pathCache[i + 1] = '\x00';
            return pathCache;
        }
    }

    return pathCache;
}

static void LoadModule(HANDLE process, const std::string & modName)
{
    void * string;
    size_t blen;
    HANDLE thread;
    std::string path;
    
    path = std::string(GetPath()).append(modName).append(".");
    blen = path.length() + 1;

    printf("Injecting %s\n", path.c_str());

    string = VirtualAllocEx(process, NULL, blen, MEM_COMMIT, PAGE_READWRITE);;

    if (!string)
    {
        printf("Couldn't commit memory to VM\n");
        return;
    }
    
    bool todo = WriteProcessMemory(process, string, path.c_str(), blen, NULL);

    thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE) LoadLibraryConstantAddress /*do you even ROP msft?*/, string, 0, NULL);

    VirtualFreeEx(process, string, blen, MEM_RELEASE);

    if (thread == INVALID_HANDLE_VALUE)
    {
        printf("Couldn't create remote thead\n");
        return;
    }

    CloseHandle(thread);
}

static constexpr bool IsDebugBuild()
{
#ifdef _DEBUG
    return true;
#else
    return false;
#endif
}

static constexpr const char * ScriptabilitySuffix(bool x32)
{
    // With any luck, a modern compile should just inline this into a routine that just returns a const string.
    if (x32)
    {
        if (IsDebugBuild())
            return ".x32.dbg.dll";
        else
            return ".x32.rel.dll";
    }
    else
    {
        if (IsDebugBuild())
            return ".x64.dbg.dll";
        else
            return ".x64.rel.dll";
    }
}

static constexpr const char * NodeSuffic(bool x32)
{
    // With any luck, a modern compile should just inline this into a routine that just returns a const string.
    if (x32)
        return ".x32.dll";
    else
        return ".x64.dll";
}

void TryInjectScriptability(int pid)
{
    HANDLE process;
    BOOL x32;
    bool fail;

    process = OpenProcess(INJECTOR_ACCESS, FALSE, pid);
    if (process == INVALID_HANDLE_VALUE)
    {
        printf("Couldn't open handle via PID\n");
        return;
    }


    fail = IsWow64Process(process, &x32);
    if (!fail)
    {
        printf("Couldn't verify the processes arch target (is IA32? AMD64? Who knows?!?!?) \n");
        return;
    }

    std::string suffix = ScriptabilitySuffix(x32);
    std::string njssuf = NodeSuffic(x32);

    LoadModule(process, std::string("Scriptability") + suffix);
    LoadModule(process, std::string("NodeJS") + njssuf);
    LoadModule(process, std::string("ScriptabilityNodeJS") + suffix);
}