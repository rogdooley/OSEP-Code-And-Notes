1. **Process and Thread Manipulation**:
    - `NtQueryInformationThread`: Can be used to query information about a thread.
    - `NtQueryInformationProcess`: Can be used to query information about a process.
2. **System Information**:
    - `GetSystemFirmwareTable`: Retrieves firmware tables from the system firmware.
    - `NtQuerySystemInformation`: Provides information about various aspects of the system.
3. **File System**:
    - `NtCreateFile`: Creates or opens a file or device.
    - `NtReadFile`: Reads data from a file.
    - `NtWriteFile`: Writes data to a file.
    - `NtQueryDirectoryFile`: Retrieves information about files in a directory.
4. **Memory Management**:
    - `NtAllocateVirtualMemory`: Reserves or commits a region of pages in the virtual address space of the specified process.
    - `NtFreeVirtualMemory`: Releases or decommits a region of pages within the virtual address space of the specified process.
5. **Registry**:
    - `NtOpenKey`: Opens a handle to the specified registry key.
    - `NtQueryValueKey`: Retrieves the type and data for the specified value name associated with an open registry key.
    - `NtSetValueKey`: Sets the data and type of a specified value under a registry key.
6. **Inter-Process Communication**:
    - `NtCreateNamedPipeFile`: Creates a named pipe.
    - `NtCreateMailslotFile`: Creates a mailslot for inter-process communication.
7. **Windows Management Instrumentation (WMI)**:
    - `IWbemLocator::ConnectServer`: Connects to a WMI namespace on a specified computer.
    - `IWbemServices::ExecQuery`: Executes a query to retrieve instances that match the query.
8. **Device and Driver Interaction**:
    - `NtDeviceIoControlFile`: Sends a control code directly to a specified device driver, causing the corresponding device to perform the specified operation.
9. **COM Interfaces**:
    - `CoCreateInstance`: Creates a single uninitialized object of the class associated with a specified CLSID.
10. **Networking**:
    - `WSARecv`: Receives data from a connected socket.
    - `WSASend`: Sends data on a connected socket.


- *NtAdjustPrivilegesToken* 
- ***NtCreateNamedPipeFile*** 
- *NtCreateFile* 
- *NtCreateMutant* 
- *NtCreateProcess*
- ***NtQueryInformationProcess***
- ***NtGetContextThread***
- *NtOpenProcess*
- *NtQuerySystemInformation*
- ***NtCreateNamedPipeFile***
- *NtReadVirtualMemory*
- *NtResumeThread*
- ***NtSetTimer***
- *NtSetContextThread*
- *NtSuspendThread*
- ***NtAllocateVirtualMemory***
- ***NtDeleteFile***
- ***NtLockFile***
- *NtAcceptConnectPort*
- *NtAccessCheck*
- *NtAlertResumeThread*
- *NtAlertThread*
- *NtCreateUserProcess*
- *NtCreateThread*
- *NtDelayExecution*
- *NtFreeVirtualMemory*
- *NtGetNextProcess*
- *NtGetNextThread*
- *NtQueryInstallUILanguage*
- *NtUnlockFile*
- *NtUnlockVirtualMemory*
- *ZwPrivilegeCheck*
- *RtlQueryRegistryValueWithFallback*
- *RtlQueryRegistryValues*
- *RtlQueryRegistryValuesEx*
- ***NtQueryDirectoryFile***
- ***NtQueryInformationProcess***
- ***NtSetInformationProcess***