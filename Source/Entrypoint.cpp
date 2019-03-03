/*
    Purpose:
    Author: J. Reece Wilson
    License: All rights reserved (2019)
*/
#include <Windows.h>
#include <iostream>
#include <string>
#include <tchar.h>
#include <psapi.h>
#include "Injecter.hpp"

// https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-processes
static void PrintProcess(int pid)
{
    BOOL x32;
    HANDLE hProcess;
    HMODULE hMod;
    DWORD cbNeeded;

    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, pid);


    if (!hProcess)
        return;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
        &cbNeeded))
    {

        GetModuleBaseName(hProcess, hMod, szProcessName,
            sizeof(szProcessName) / sizeof(TCHAR));
    }

    IsWow64Process(hProcess, &x32);

    _tprintf(TEXT("%s  %-50s (PID: %u)\n"), x32 ? "x86_32" : "x86_64", szProcessName, pid);

    CloseHandle(hProcess);
}

// https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-processes
static void ListProcesses()
{
    DWORD aProcesses[1024 * 10], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        printf("Couldn't enumerate procsses\n");
        return;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] == 0)
            continue;

        PrintProcess(aProcesses[i]);
    }
}

static void ListWindows()
{
    puts("TODO: ");
}

static void Connect(int pid)
{
    TryInjectScriptablity(pid);
}

int main(int argc, const char ** argv)
{
    std::string line;

    std::cout << "Scriptablity Injection Utility" << std::endl;
    std::cout << " Copyright © All rights reserved, J.Reece Wilson 2019-???? ";
    std::cout << std::endl << std::endl;

    std::cout << "Warning: if you're playing with chrome/fx processes, you need to nuke their sandboxes (hint: about:config, 'sandbox' integers, or --no-sandbox)" << std::endl;
    std::cout << "For products with anti-tamper, you may want to fork github.com/ReeceSX/ScriptablityCore and reimplement ./OS/Win32" << std::endl;

    std::cout << std::endl << std::endl;

    std::cout << "Commands: " << std::endl;
    std::cout << "\tprocesses" << std::endl;
    std::cout << "\twindows" << std::endl;
    std::cout << "\tconnect <pid>" << std::endl;

    std::cout << std::endl;

    while (std::getline(std::cin, line))
    {
        if (line.find("processes") == 0)
        {
            ListProcesses();
            continue;
        }

        if (line.find("windows") == 0)
        {
            ListWindows();
            continue;
        }

        if (line.find("connect ") == 0)
        {
            int pid = std::stoi(line.substr(8));
            Connect(pid);
            continue;
        }
    }

}