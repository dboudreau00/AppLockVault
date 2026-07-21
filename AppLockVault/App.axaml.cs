using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace AppLockVault;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        // Last-resort nets. Per-action handlers deal with expected failures locally; these catch
        // stray background/task exceptions so they can't take the process down silently.
        // (Avalonia has no single UI-thread "unhandled exception" event like WPF, so UI safety
        //  relies on the try/catch in every handler.)
        AppDomain.CurrentDomain.UnhandledException += (_, _) => { /* best-effort */ };
        TaskScheduler.UnobservedTaskException += (_, e) => e.SetObserved();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            desktop.MainWindow = new MainWindow();

        base.OnFrameworkInitializationCompleted();
    }
}
