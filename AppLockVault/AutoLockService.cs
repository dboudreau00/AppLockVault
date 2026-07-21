using System;
using Avalonia.Threading;

namespace AppLockVault;

/// <summary>
/// Idle auto-lock. Call Reset() on any user interaction; when the idle window elapses it fires
/// onElapsed (which should drop keys via ProtectionEngine.Lock()).
/// </summary>
public sealed class AutoLockService
{
    private readonly DispatcherTimer _timer;
    private readonly Action _onElapsed;

    public AutoLockService(int seconds, Action onElapsed)
    {
        _onElapsed = onElapsed ?? throw new ArgumentNullException(nameof(onElapsed));
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(Math.Max(1, seconds)) };
        _timer.Tick += (_, _) =>
        {
            _timer.Stop();
            // A failure here (e.g. a UI refresh) must not surface as a crash. Keys are dropped by
            // Lock() before any UI work, so the security action still completes.
            try { _onElapsed(); }
            catch { /* ignore */ }
        };
    }

    public void Start() { _timer.Stop(); _timer.Start(); }
    public void Reset() => Start();
    public void Stop() => _timer.Stop();

    public void UpdateInterval(int seconds)
        => _timer.Interval = TimeSpan.FromSeconds(Math.Max(1, seconds));
}
