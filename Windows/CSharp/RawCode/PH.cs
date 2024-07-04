using System;
using System.IO;
using System.Net.Http;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        var rootCommand = new RootCommand
        {
            new Option<string>(
                new[] { "-k", "--key" },
                description: "Base64 encoded key from the command line"),
            new Option<string>(
                new[] { "-t", "--target-url" },
                description: "URL to fetch the base64 encoded key"),
            new Option<string>(
                new[] { "-i", "--import" },
                description: "File path to import the binary array"),
            new Option<string>(
                new[] { "-b", "--binary-url" },
                description: "URL to fetch the binary array")
        };

        rootCommand.Description = "A program to read and decode keys and binary arrays.";

        rootCommand.Handler = CommandHandler.Create<string, string, string, string>(async (key, targetUrl, import, binaryUrl) =>
        {
            string keyValue = null;
            byte[] binaryArray = null;

            if (!string.IsNullOrEmpty(key))
            {
                keyValue = key;
            }

            if (!string.IsNullOrEmpty(targetUrl))
            {
                keyValue = await ReadKeyFromUrl(targetUrl);
            }

            if (!string.IsNullOrEmpty(import))
            {
                binaryArray = File.ReadAllBytes(import);
            }

            if (!string.IsNullOrEmpty(binaryUrl))
            {
                binaryArray = await ReadBinaryFromUrl(binaryUrl);
            }

            // Decode the key if it was provided
            if (!string.IsNullOrEmpty(keyValue))
            {
                byte[] decodedKey = Convert.FromBase64String(keyValue);
                Console.WriteLine($"Decoded Key: {BitConverter.ToString(decodedKey)}");
            }

            // If binary array was read in, process it
            if (binaryArray != null)
            {
                Console.WriteLine($"Binary Array Length: {binaryArray.Length}");
                // Add your decryption logic here
            }
        });

        await rootCommand.InvokeAsync(args);
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

