/*
    Purpose:
    Author: J. Reece Wilson
    License: All rights reserved (2019)
*/
#include <Windows.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <tchar.h>
#include <psapi.h>
#include "Injecter.hpp"

static std::map<DWORD, std::pair<HANDLE, std::vector<std::string>>*> windowHandles;

// https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-processes

static std::string StripPath(PTCHAR mod)
{
    size_t i;

    for (i = strlen(mod); i != 0; i--)
        if (mod[i] == '\\')
            break;

    if (i != 0)
        i++;

    return std::string(&mod[i]);
}


static void PrintProcess(HANDLE hProcess, DWORD pid, std::vector<std::string> & windows)
{
    BOOL x32;
    HANDLE hDup;
    DWORD length = MAX_PATH;
    TCHAR szProcessName[MAX_PATH + 1];
    std::string title;
    std::string process;

    hDup = OpenProcess(INJECTOR_ACCESS, false, pid);

    if (QueryFullProcessImageNameA(hProcess, 0, szProcessName, &length))
        process = StripPath(szProcessName);
    else
        process = "<permission error>";

    if (!IsWow64Process(hProcess, &x32))
    {
        printf("Couldn't enum process - IsWow64Process failed. Error: 0x%x\n", GetLastError());
        return;
    }

    if (windows.size() == 1)
        title = std::string(windows[0]).append(" (").append(process).append(")");
    else
        title = process;

    printf("%s  %-75s (PID: %u, Injectable: %s)\n", x32 ? "x86_32" : "x86_64", title.c_str(), pid, hDup == INVALID_HANDLE_VALUE ? "false" : "true");

    if (windows.size() > 1)
    {
        for (const auto & window : windows)
            printf("\tWindow: %-25s\n", window.c_str());
    }

    if (windows.size() != 0)
        printf("\n");

    if (hDup != INVALID_HANDLE_VALUE)
        CloseHandle(hDup);
}

// https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-processes
static void ListProcesses()
{
    std::vector<std::string> windows;
    DWORD aProcesses[1024 * 10], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        printf("Couldn't enumerate processes (error: 0x%x)\n", GetLastError());
        return;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (i = 0; i < cProcesses; i++)
    {
        HANDLE handle;
        DWORD pid = aProcesses[i];

        if (pid == 0)
            continue;

        handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!handle)
            continue;

        PrintProcess(handle, pid, windows);

        CloseHandle(handle);
    }
}

static void AddWindowToCache(HWND window, DWORD pid)
{
    int err;
    TCHAR buffer[401];

    err = GetWindowTextA(window, buffer, sizeof(buffer) - 1);
    if (!err)
        return;

    if ((err > 2) && (buffer[1] == ':') && (buffer[2] == '\\'))
        windowHandles[pid]->second.push_back(StripPath(buffer));
    else
        windowHandles[pid]->second.push_back(buffer);
}

BOOL CALLBACK EnumWindowsProc(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
)
{
    HANDLE handle;
    std::string title;
    DWORD pid = 0;

    if (!IsWindowVisible(hwnd))
        return true;

    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0)
        return true;

    if (windowHandles.find(pid) == windowHandles.end())
    {
        handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!handle)
            return true;

        windowHandles[pid] = new std::pair<HANDLE, std::vector<std::string>>(handle, std::vector<std::string>());
    }

    AddWindowToCache(hwnd, pid);
    return true;
}

static void ListWindows(bool all)
{
    if (!EnumWindows(EnumWindowsProc, NULL))
    {
        printf("Couldn't enumerate Windows (error: 0x%x)\n", GetLastError());
        return;
    }

    for (const auto & a : windowHandles)
    {
        HANDLE handle = a.second->first;
        std::vector<std::string> windows = a.second->second;

        if ((windows.size() > 3) && (!all))
        {
            windows.erase(windows.begin() + 2, windows.end());
            windows.push_back("...");
        }

        PrintProcess(handle, GetProcessId(handle), windows);

        CloseHandle(handle);
        delete a.second;
    }

    windowHandles.clear();
}

static void Connect(int pid)
{
    TryInjectScriptability(pid);

    if (GetCurrentProcessId() != pid)
        return;

    while (1)
        Sleep(0xFFFFFFFF);
}

int main(int argc, const char ** argv)
{
    std::string line;

    std::cout << "Scriptability Injection Utility" << std::endl;
    std::cout << " Copyright © All rights reserved, J.Reece Wilson 2019-???? ";
    std::cout << std::endl << std::endl;

    std::cout << "Warning: if you're playing with chrome/fx processes, you need to nuke their sandboxes (hint: about:config, 'sandbox' integers, or --no-sandbox)" << std::endl;
    std::cout << "For products with anti-tamper, you may want to fork and reimplement ./OS/Win32 and/or the injector" << std::endl;

    std::cout << std::endl << std::endl;

    std::cout << "Commands: " << std::endl;
    std::cout << "\tprocesses      | Lists all processes" << std::endl;
    std::cout << "\twindows        | Lists windows (limited 3 per process)" << std::endl;
    std::cout << "\twindows all    | Lists all Windows (without truncating)" << std::endl;
    std::cout << "\tconnect <pid>  | Injects the Scriptability modules into the target process" << std::endl;

    std::cout << std::endl;

    while (std::getline(std::cin, line))
    {
        if (line.find("processes") == 0)
        {
            ListProcesses();
            continue;
        }

        if (line.find("windows all") == 0)
        {
            ListWindows(true);
            continue;
        }

        if (line.find("windows") == 0)
        {
            ListWindows(false);
            continue;
        }

        if (line.find("connect ") == 0)
        {
            Connect(std::stoi(line.substr(8)));
            continue;
        }

        printf("Unknown command!\n");
    }
}