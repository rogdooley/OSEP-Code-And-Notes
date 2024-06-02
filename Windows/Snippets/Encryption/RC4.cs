using System;

public class RC4
{
    private byte[] S = new byte[256];
    private int x = 0;
    private int y = 0;

    public RC4(byte[] key)
    {
        for (int i = 0; i < 256; i++)
        {
            S[i] = (byte)i;
        }

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] + key[i % key.Length]) % 256;
            Swap(i, j);
        }
    }

    private void Swap(int i, int j)
    {
        byte temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    public byte[] Encrypt(byte[] data)
    {
        byte[] buffer = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            x = (x + 1) % 256;
            y = (y + S[x]) % 256;
            Swap(x, y);
            int xorIndex = (S[x] + S[y]) % 256;
            buffer[i] = (byte)(data[i] ^ S[xorIndex]);
        }
        return buffer;
    }

    public byte[] Decrypt(byte[] data)
    {
        // RC4 encryption and decryption are symmetric
        return Encrypt(data);
    }
}

public class Program
{
    public static void Main()
    {
        byte[] key = System.Text.Encoding.UTF8.GetBytes("your-key");
        byte[] data = System.Text.E
