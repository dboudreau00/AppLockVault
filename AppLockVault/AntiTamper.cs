using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace AppLockVault;

/// <summary>
/// HONEST WARNING: these checks are trivially bypassed (patch the bytes, kernel-mode debugger,
/// hypervisor). They raise the bar only slightly. Real anti-reverse-engineering for a shipping
/// product = NativeAOT (no IL to decompile) + an obfuscator + a commercial packer + code signing.
/// Now cross-platform: the Windows-only checks are guarded; other OSes fall back to the managed one.
/// </summary>
public static class AntiTamper
{
    [DllImport("kernel32.dll")] private static extern bool IsDebuggerPresent();
    [DllImport("kernel32.dll")] private static extern bool CheckRemoteDebuggerPresent(IntPtr h, ref bool present);

    public static bool DebuggerDetected()
    {
        if (Debugger.IsAttached) return true;
        if (OperatingSystem.IsWindows()) return WindowsChecks();
        return false;
    }

    [SupportedOSPlatform("windows")]
    private static bool WindowsChecks()
    {
        try
        {
            if (IsDebuggerPresent()) return true;
            bool remote = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref remote);
            return remote;
        }
        catch { return false; }
    }
}
