using Microsoft.Win32;

public class BrowserDetection
{
    public string GetBrowserUserAgent()
    {
        string[] browsers = { "Edge", "Chrome", "Firefox", "Brave", "Vivaldi" };
        foreach (var browser in browsers)
        {
            if (IsBrowserInstalled(browser))
            {
                return GetUserAgent(browser);
            }
        }
        // Default to Chrome if none are found
        return GetUserAgent("Chrome");
    }

    private bool IsBrowserInstalled(string browserName)
    {
        string browserKey = @"SOFTWARE\Clients\StartMenuInternet\" + browserName;
        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(browserKey))
        {
            return key != null;
        }
    }

    private string GetUserAgent(string browserName)
    {
        // User-agent strings can be updated with the latest versions
        switch (browserName)
        {
            case "Edge":
                return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36 Edg/100.0.1185.39";
            case "Chrome":
                return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36";
            case "Firefox":
                return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0";
            case "Brave":
                return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36 Brave/100.0.0.0";
            case "Vivaldi":
                return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36 Vivaldi/100.0.0.0";
            default:
                return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36";
        }
    }
}

