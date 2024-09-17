## Enable SeDebugPrivileges for an Admin user if it's disabled
## Avoids having to run something like FullPowers and getting yet another shell

$definition = @"
using System;
using System.Runtime.InteropServices;

public class Privilege {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges, ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr processHandle, int desiredAccess, ref IntPtr tokenHandle);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public LUID Luid;
        public int Attributes;
    }

    const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const int TOKEN_QUERY = 0x0008;
    const int SE_PRIVILEGE_ENABLED = 0x00000002;

    public static void EnablePrivilege(string privilege) {
        IntPtr tokenHandle = IntPtr.Zero;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref tokenHandle);

        LUID luid = new LUID();
        LookupPrivilegeValue(null, privilege, ref luid);

        TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES();
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Luid = luid;
        tokenPrivileges.Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
"@
Add-Type -TypeDefinition $definition

# Enabling SeDebugPrivilege
[Privilege]::EnablePrivilege("SeDebugPrivilege")
Write-Host "SeDebugPrivilege enabled."

