/*
    Purpose:
    Author: J. Reece Wilson
    License: All rights reserved (2019)
*/
#pragma once

#define INJECTOR_ACCESS PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE

extern void TryInjectScriptability(int pid);