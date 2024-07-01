using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        string key = null;
        byte[] binaryArray = null;

        // Parse command line arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-k":
                case "--key":
                    if (i + 1 < args.Length)
                    {
                        key = args[++i];
                    }
                    break;
                case "-t":
                case "--target-url":
                    if (i + 1 < args.Length)
                    {
                        key = await ReadKeyFromUrl(args[++i]);
                    }
                    break;
                case "-i":
                case "--import":
                    if (i + 1 < args.Length)
                    {
                        binaryArray = File.ReadAllBytes(args[++i]);
                    }
                    break;
                case "-b":
                case "--binary-url":
                    if (i + 1 < args.Length)
                    {
                        binaryArray = await ReadBinaryFromUrl(args[++i]);
                    }
                    break;
            }
        }

        // Decode the key if it was provided
        if (!string.IsNullOrEmpty(key))
        {
            byte[] decodedKey = Convert.FromBase64String(key);
            Console.WriteLine($"Decoded Key: {BitConverter.ToString(decodedKey)}");
        }

        // If binary array was read in, process it
        if (binaryArray != null)
        {
            Console.WriteLine($"Binary Array Length: {binaryArray.Length}");
            // Add your decryption logic here
        }
    }

    static async Task<string> ReadKeyFromUrl(string url)
    {
        using (HttpClient client = new HttpClient())
        {
            try
            {
                string key = await client.GetStringAsync(url);
                return key.Trim();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading key from URL: {ex.Message}");
                return null;
            }
        }
    }

    static async Task<byte[]> ReadBinaryFromUrl(string url)
    {
        using (HttpClient client = new HttpClient())
        {
            try
            {
                byte[] binaryData = await client.GetByteArrayAsync(url);
                return binaryData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading binary data from URL: {ex.Message}");
                return null;
            }
        }
    }
}

