using System;
using Avalonia;

namespace AppLockVault;

internal static class Program
{
    // Avalonia entry point. Keep initialisation minimal here; app setup lives in App.
    [STAThread]
    public static void Main(string[] args) => BuildAvaloniaApp()
        .StartWithClassicDesktopLifetime(args);

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
