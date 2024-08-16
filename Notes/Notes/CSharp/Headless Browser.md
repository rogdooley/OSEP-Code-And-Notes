
Yes, it is possible to use a headless browser to download a file into memory in C#. You can use libraries like Selenium WebDriver for this purpose. Here is an example using Selenium WebDriver with Chrome in headless mode. This example demonstrates how to set up the browser in headless mode and download a file into memory.

First, you need to install the Selenium WebDriver and ChromeDriver:

1. Install the Selenium WebDriver NuGet package:
   ```sh
   dotnet add package Selenium.WebDriver
   ```

2. Install the Chrome WebDriver NuGet package:
   ```sh
   dotnet add package Selenium.WebDriver.ChromeDriver
   ```

Then, you can use the following C# code to perform the download in headless mode:

```csharp
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using System;
using System.IO;
using System.Net;
using System.Threading;

class Program
{
    static void Main()
    {
        var chromeOptions = new ChromeOptions();
        chromeOptions.AddArguments("--headless");
        chromeOptions.AddArguments("--disable-gpu");
        chromeOptions.AddArguments("--disable-extensions");
        chromeOptions.AddArguments("--no-sandbox");
        chromeOptions.AddArguments("--disable-dev-shm-usage");

        // Specify the download directory
        string downloadDirectory = Path.Combine(Path.GetTempPath(), "Downloads");
        Directory.CreateDirectory(downloadDirectory);

        // Configure Chrome to automatically download files
        chromeOptions.AddUserProfilePreference("download.default_directory", downloadDirectory);
        chromeOptions.AddUserProfilePreference("download.prompt_for_download", false);
        chromeOptions.AddUserProfilePreference("download.directory_upgrade", true);
        chromeOptions.AddUserProfilePreference("safebrowsing.enabled", true);

        IWebDriver driver = new ChromeDriver(chromeOptions);
        try
        {
            string url = "https://example.com/file-to-download";

            driver.Navigate().GoToUrl(url);

            // Wait for the file to be downloaded
            Thread.Sleep(5000);

            // Read the downloaded file into memory
            string downloadedFilePath = Directory.GetFiles(downloadDirectory)[0];
            byte[] fileBytes = File.ReadAllBytes(downloadedFilePath);

            Console.WriteLine($"Downloaded {fileBytes.Length} bytes");

            // Clean up
            File.Delete(downloadedFilePath);
        }
        finally
        {
            driver.Quit();
        }
    }
}
```

This code sets up a headless Chrome browser, navigates to a specified URL to download a file, waits for the file to be downloaded, reads the file into memory as a byte array, and then cleans up.

Please note that this example assumes the download will complete within 5 seconds (as specified in the `Thread.Sleep` call). In a real-world scenario, you would want to implement a more robust waiting mechanism to ensure the file has fully downloaded before attempting to read it.

If you want to download a file in memory using Edge without using Selenium, you can use the WebView2 control provided by Microsoft. WebView2 allows you to embed the Chromium-based Edge browser in your application. Here's how you can use WebView2 to download a file into memory in headless mode:

First, install the WebView2 NuGet package:

```sh
dotnet add package Microsoft.Web.WebView2
```

Then, you can use the following C# code to perform the download:

```csharp
using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Web.WebView2.Core;

class Program
{
    static async Task Main(string[] args)
    {
        // Specify the URL to download the file from
        string url = "https://example.com/file-to-download";

        // Initialize the WebView2 environment
        var webView2Environment = await CoreWebView2Environment.CreateAsync();
        var webView2 = new CoreWebView2ControllerOptions(webView2Environment);

        // Create a temporary file to use as the WebView2 download path
        string tempFilePath = Path.GetTempFileName();

        // Navigate to the URL and wait for the download to complete
        webView2.CoreWebView2.NavigationCompleted += async (sender, e) =>
        {
            if (e.IsSuccess)
            {
                // Download the file
                using (HttpClient client = new HttpClient())
                {
                    byte[] fileBytes = await client.GetByteArrayAsync(url);
                    Console.WriteLine($"Downloaded {fileBytes.Length} bytes");

                    // Process the downloaded file bytes as needed
                }
            }
            else
            {
                Console.WriteLine("Navigation failed.");
            }

            // Clean up
            webView2.Close();
        };

        // Initialize the WebView2 controller
        var options = new CoreWebView2ControllerOptions();
        var webView2Controller = await CoreWebView2Controller.CreateAsync(webView2Environment, tempFilePath, options);

        // Navigate to the URL
        await webView2Controller.NavigateAsync(url);

        // Wait for the download to complete
        await Task.Delay(10000); // Adjust the delay as needed
    }
}
```

In this example, we initialize the WebView2 environment and create a temporary file to use as the WebView2 download path. We navigate to the specified URL and use an `HttpClient` to download the file into memory. The downloaded file bytes are then printed to the console.

Please note that WebView2 is still evolving, and some features might not be fully supported in the current version. Additionally, the above code assumes that the file download will complete within a specified delay. You might need to implement a more robust mechanism to ensure the download completes before processing the file.

If you need to download files using a headless browser without requiring the WebView2 runtime or any other runtime to be installed on the client machine, C++ might be a more suitable option, particularly because you can use libraries that allow for headless browsing without additional dependencies.

However, if you prefer to stick with C#, you can use Selenium WebDriver in headless mode with Chrome or Edge. This approach will still require the WebDriver executables, but it avoids the need for WebView2 runtime installation.

Here's an example of how you could use Selenium WebDriver in C# to download a file using Chrome in headless mode:

### C# Solution Using Selenium WebDriver

1. **Set Up Your Project**

   Create a new .NET project and add the necessary packages:

   ```sh
   dotnet new console -n HeadlessDownload
   cd HeadlessDownload
   dotnet add package Selenium.WebDriver
   dotnet add package Selenium.WebDriver.ChromeDriver
   ```

2. **Write the Code**

   Create a `Program.cs` file with the following content:

   ```csharp
   using System;
   using OpenQA.Selenium;
   using OpenQA.Selenium.Chrome;

   class Program
   {
       static void Main(string[] args)
       {
           string downloadUrl = "https://example.com/file-to-download";
           string downloadFilePath = "/path/to/downloaded/file";

           ChromeOptions options = new ChromeOptions();
           options.AddArgument("--headless");
           options.AddUserProfilePreference("download.default_directory", downloadFilePath);
           options.AddUserProfilePreference("download.prompt_for_download", false);
           options.AddUserProfilePreference("disable-popup-blocking", "true");

           using (IWebDriver driver = new ChromeDriver(options))
           {
               driver.Navigate().GoToUrl(downloadUrl);
               Console.WriteLine("Download started...");
               // Wait for the download to complete
               System.Threading.Thread.Sleep(10000); // Adjust the delay as needed
           }

           Console.WriteLine("Download completed.");
       }
   }
   ```

3. **Build and Run the Project**

   ```sh
   dotnet build
   dotnet run
   ```

### C++ Solution Using libcurl

If you prefer to avoid any additional dependencies and go with C++, you can use the `libcurl` library to perform HTTP requests. This approach won't provide headless browser functionality but will allow you to download files directly.

1. **Install libcurl**

   Ensure `libcurl` is installed on your system. On Windows, you can download the precompiled binaries from the [curl website](https://curl.se/windows/).

2. **Write the C++ Code**

   Create a file `download.cpp` with the following content:

   ```cpp
   #include <iostream>
   #include <fstream>
   #include <curl/curl.h>

   size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
   {
       ((std::string*)userp)->append((char*)contents, size * nmemb);
       return size * nmemb;
   }

   int main()
   {
       CURL* curl;
       CURLcode res;
       std::string readBuffer;

       curl = curl_easy_init();
       if(curl) {
           curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/file-to-download");
           curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
           curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
           res = curl_easy_perform(curl);
           curl_easy_cleanup(curl);

           if(res != CURLE_OK)
               std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;

           std::ofstream outFile("downloaded_file");
           outFile << readBuffer;
           outFile.close();

           std::cout << "Download completed." << std::endl;
       }
       return 0;
   }
   ```

3. **Compile and Run the C++ Code**

   On Windows, you can use a compiler like MSVC:

   ```sh
   cl /EHsc download.cpp /link libcurl.lib
   download.exe
   ```

   On Linux, you can use `g++`:

   ```sh
   g++ download.cpp -o download -lcurl
   ./download
   ```

### Conclusion

Both C# with Selenium WebDriver and C++ with libcurl are viable options. C++ with libcurl is more lightweight and avoids any runtime dependencies, making it more suitable if you need to ensure no additional software installations are required. On the other hand, C# with Selenium WebDriver provides more control and functionality akin to a headless browser, but it comes with the overhead of requiring the WebDriver executable.