using System;
using System.Net;
using System.Net.Security;

public class HttpRequestHandler
{
    private string baseUrl;

    public HttpRequestHandler(string baseUrl)
    {
        this.baseUrl = baseUrl;
    }

    public string SendGetRequest(string relativeUrl)
    {
        string fullUrl = $"{baseUrl}/{relativeUrl}";
        using (var client = new WebClient())
        {
            // Set the User-Agent header
            client.Headers[HttpRequestHeader.UserAgent] = browserDetection.GetBrowserUserAgent();

            // Ignore SSL certificate validation
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });

            try
            {
                return client.DownloadString(fullUrl);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during GET request: {ex.Message}");
                return null;
            }
        }
    }

    public void SendPostRequest(string relativeUrl, string data)
    {
        string fullUrl = $"{baseUrl}/{relativeUrl}";
        using (var client = new WebClient())
        {
            // Set the User-Agent header
            client.Headers[HttpRequestHeader.UserAgent] = browserDetection.GetBrowserUserAgent();

            // Ignore SSL certificate validation
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });

            try
            {
                client.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                client.UploadString(fullUrl, data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during POST request: {ex.Message}");
            }
        }
    }
}
