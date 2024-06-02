using System;
using System.IO;
using System.Security.Cryptography;

public class AesEncryption
{
    public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(data, 0, data.Length);
                    csEncrypt.FlushFinalBlock();
                    return msEncrypt.ToArray();
                }
            }
        }
    }

    public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream msPlain = new MemoryStream())
                    {
                        csDecrypt.CopyTo(msPlain);
                        return msPlain.ToArray();
                    }
                }
            }
        }
    }

    public static void Main()
    {
        // Example usage
        byte[] key = Convert.FromBase64String("your-base64-encoded-key");
        byte[] iv = Convert.FromBase64String("your-base64-encoded-iv");
        byte[] original = System.Text.Encoding.UTF8.GetBytes("Here is some data to encrypt!");

        Console.WriteLine("Original: " + System.Text.Encoding.UTF8.GetString(original));

        // Encrypt
        byte[] encrypted = Encrypt(original, key, iv);
        Console.WriteLine("Encrypted: " + Convert.ToBase64String(encrypted));

        // Decrypt
        byte[] decrypted = Decrypt(encrypted, key, iv);
        Console.WriteLine("Decrypted: " + System.Text.Encoding.UTF8.GetString(decrypted));
    }
}
