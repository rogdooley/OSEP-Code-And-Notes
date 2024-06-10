Function RC4(key, data)
    Dim S(255)
    Dim i, j, l, temp, K(255), ciphertext()
    ReDim ciphertext(UBound(data))
    
    ' Initialize S and K
    For i = 0 To 255
        S(i) = i
        K(i) = Asc(Mid(key, (i Mod Len(key)) + 1, 1))
    Next
    
    j = 0
    ' Initial Permutation of S
    For i = 0 To 255
        j = (j + S(i) + K(i)) Mod 256
        temp = S(i)
        S(i) = S(j)
        S(j) = temp
    Next
    
    i = 0
    j = 0
    
    For l = 0 To UBound(data)
        i = (i + 1) Mod 256
        j = (j + S(i)) Mod 256
        temp = S(i)
        S(i) = S(j)
        S(j) = temp
        t = (S(i) + S(j)) Mod 256
        ciphertext(l) = data(l) Xor S(t)
    Next
    
    RC4 = ciphertext
End Function

Function ByteArrayToString(byteArray)
    Dim i, result
    result = ""
    For i = 0 To UBound(byteArray)
        result = result & Chr(byteArray(i))
    Next
    ByteArrayToString = result
End Function

' Encrypted byte array from Python
Dim encrypted
encrypted = Array(&H90, &Haf, &Hf7, &H78, &H5d, &H62, &H33, &Ha7, &Ha1, &H9d, &H20, &Hc7, &Ha7, &H61, &H9c, &H3b, &H7b, &Hd8, &H6e, &Hc9, &Hcb, &H61, &He6, &Ha8, &Hf0, &H94, &H61, &H77, &Hf9, &H3d, &H0d, &H62, &Hc1, &Hb1, &H3d, &H50, &H25, &Hac, &He4, &Hbb, &Hda, &Hd5, &Ha4, &H5b, &Haf, &H67, &Hd8, &H80, &H53, &H00, &H96, &Hfc, &Hdd, &Hc1, &H8d, &Hdf, &H69, &H9b, &H2a, &H0f, &Hf0, &H78, &H45, &H2f, &H43, &H56, &Hfa, &H98, &Hd5, &Hce, &H08, &H09, &Hbb, &H48, &H3a, &H50, &H8d, &H9e, &Hd3, &Hc9, &Hb9, &H4f, &H25, &Hfe, &H93, &H06, &H13, &H3e, &Hc3, &Hd1, &H36, &H15, &H21, &Hf2, &H1e, &Hde, &H7b, &H9d, &H44, &H40, &H5a, &H44, &H2c, &Hc0, &H40, &H1a, &H61, &Hee, &Hf9, &Hec, &H49, &Hd2, &Hf3, &Hf4, &H0d, &H6c, &H12, &H12, &Hec, &Hda, &H88, &H19, &H9a, &Hc5, &H48, &H4d, &H13, &H9a, &H84) ' replace with your byte array

Dim key
key = "myprivatekey"

Dim decrypted
decrypted = RC4(key, encrypted)

Dim decryptedString
decryptedString = ByteArrayToString(decrypted)

WScript.Echo "Decrypted string: " & decryptedString

