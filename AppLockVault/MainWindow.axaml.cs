using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace AppLockVault;

public partial class MainWindow : Window
{
    private ProtectionEngine? _engine;   // null only if secure-storage init failed (handled in OnOpened)
    private AutoLockService? _autoLock;
    private string? _initError;

    public MainWindow()
    {
        InitializeComponent();

        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AppLockVault");
            _engine = new ProtectionEngine(dir);
            _engine.Locked += () => Dispatcher.UIThread.Post(ShowLockedOrSetup);
        }
        catch (Exception ex)
        {
            _initError = ex.Message;
        }

        AddHandler(KeyDownEvent, (_, _) => _autoLock?.Reset(), RoutingStrategies.Tunnel);
        AddHandler(PointerMovedEvent, (_, _) => _autoLock?.Reset(), RoutingStrategies.Tunnel);

        ShowLockedOrSetup();
    }

    protected override async void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        if (AntiTamper.DebuggerDetected())
        {
            await Dialog.Error(this, "AppLock Vault", "Debugger detected.\n\nThe application will now close.");
            Close();
            return;
        }
        if (_initError is not null)
        {
            await Dialog.Error(this, "AppLock Vault",
                "Could not initialise secure storage:\n\n" + _initError + "\n\nThe application will now close.");
            Close();
        }
    }

    private void ShowLockedOrSetup()
    {
        _autoLock?.Stop();
        SetupPanel.IsVisible = false;
        LockedPanel.IsVisible = false;
        UnlockedPanel.IsVisible = false;
        if (_engine is null) return;

        if (!_engine.IsProvisioned)
        {
            StatusText.Text = "No vault yet — create one to begin.";
            SetupPanel.IsVisible = true;
        }
        else
        {
            StatusText.Text = "Locked.";
            LockedPanel.IsVisible = true;
            UnlockPassword.Text = "";
            UnlockPassword.Focus();
        }
    }

    private void ShowUnlocked()
    {
        if (_engine is null) return;
        SetupPanel.IsVisible = false;
        LockedPanel.IsVisible = false;
        UnlockedPanel.IsVisible = true;
        StatusText.Text = "Unlocked.";
        UnlockedInfo.Text = "";
        RefreshFolderUi();

        var cfg = _engine.LoadConfig();
        if (_autoLock is null) _autoLock = new AutoLockService(cfg.AutoLockSeconds, AutoLockElapsed);
        else _autoLock.UpdateInterval(cfg.AutoLockSeconds);
        _autoLock.Start();
    }

    // Drives the folder UI off the authoritative locked flag, never off whether the path exists.
    private void RefreshFolderUi()
    {
        if (_engine is null) return;
        var path = _engine.GetProtectedFolderPath();
        bool locked = _engine.IsFolderLocked();

        if (string.IsNullOrEmpty(path))
        {
            FolderStatus.Text = "No folder is protected yet. Choose one to lock it away.";
            BtnLockFolder.Content = "Lock a folder…";
            BtnLockFolder.IsVisible = true;
            BtnOpenFolder.IsVisible = false;
            BtnForgetFolder.IsVisible = false;
        }
        else if (locked)
        {
            FolderStatus.Text = "🔒 LOCKED — encrypted in vault:\n" + path;
            BtnLockFolder.IsVisible = false;
            BtnOpenFolder.IsVisible = true;
            BtnForgetFolder.IsVisible = false;
        }
        else
        {
            FolderStatus.Text = "📂 OPEN — readable on disk:\n" + path;
            BtnLockFolder.Content = "Lock folder";
            BtnLockFolder.IsVisible = true;
            BtnOpenFolder.IsVisible = false;
            BtnForgetFolder.IsVisible = true;
        }
    }

    private async void OnCreateVault(object? sender, RoutedEventArgs e)
    {
        if (_engine is null) return;
        var m = SetupMaster.Text ?? "";
        var mc = SetupMasterConfirm.Text ?? "";
        var d = SetupDuress.Text ?? "";

        if (m.Length < 8) { await Dialog.Error(this, "Check password", "Master password must be at least 8 characters."); return; }
        if (m != mc) { await Dialog.Error(this, "Check password", "Master passwords do not match."); return; }
        if (string.IsNullOrWhiteSpace(d)) { await Dialog.Error(this, "Check password", "Enter a duress password."); return; }
        if (m == d) { await Dialog.Error(this, "Check password", "Duress password must differ from the master password."); return; }

        int.TryParse(SetupAutoLock.Text, out var autoSecs);
        int.TryParse(SetupDuressCount.Text, out var duressCount);
        var cfg = new VaultConfig
        {
            AutoLockSeconds = autoSecs <= 0 ? 300 : autoSecs,
            DuressTriggerCount = duressCount <= 0 ? 1 : duressCount
        };

        try
        {
            _engine.Setup(m, d, cfg);
            await Dialog.Info(this, "AppLock Vault", "Vault created. It is now locked.");
            ShowLockedOrSetup();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or VaultException)
        { await Dialog.Error(this, "Error", ex.Message); }
        catch (Exception ex)
        { await Dialog.Error(this, "Error", "Could not create the vault: " + ex.Message); }
    }

    private void OnUnlockKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) OnUnlock(sender, e);
    }

    private async void OnUnlock(object? sender, RoutedEventArgs e)
    {
        if (_engine is null) return;
        UnlockError.Text = "";

        UnlockResult result;
        try { result = _engine.TryUnlock(UnlockPassword.Text ?? ""); }
        catch (VaultException ex) { UnlockPassword.Text = ""; await OfferVaultReset(ex.Message); return; }
        catch (Exception ex) { UnlockPassword.Text = ""; await Dialog.Error(this, "Error", "Unexpected error while unlocking: " + ex.Message); return; }
        UnlockPassword.Text = "";

        switch (result)
        {
            case UnlockResult.Unlocked: ShowUnlocked(); break;
            case UnlockResult.Wiped: await Dialog.Info(this, "AppLock Vault", "Vault wiped."); ShowLockedOrSetup(); break;
            case UnlockResult.LockedOut: UnlockError.Text = "Too many attempts — locked out."; break;
            case UnlockResult.NotProvisioned: ShowLockedOrSetup(); break;
            default: UnlockError.Text = "Incorrect password."; break;
        }
    }

    private async void OnLockFolder(object? sender, RoutedEventArgs e)
    {
        if (_engine is null) return;

        var current = _engine.GetProtectedFolderPath();
        bool locked = _engine.IsFolderLocked();

        string target;
        if (!string.IsNullOrEmpty(current) && !locked)
        {
            target = current; // re-lock the folder that's currently open
        }
        else
        {
            var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = "Choose a folder to lock",
                AllowMultiple = false
            });
            if (folders.Count == 0) return;
            target = folders[0].Path.LocalPath;
        }

        var go = await Dialog.Confirm(this, "Lock this folder?",
            "This encrypts:\n\n" + target + "\n\ninto the vault and then removes the original from disk. " +
            "You'll need your password to open it again.\n\n" +
            "Tip: securely erasing the original is best-effort on SSDs — keep disk encryption " +
            "(BitLocker / FileVault) on for full at-rest protection.");
        if (!go) return;

        try
        {
            _engine.LockFolder(target);
            RefreshFolderUi();
            UnlockedInfo.Text = "Folder locked. Only encrypted data remains on disk.";
        }
        catch (Exception ex)
        {
            await Dialog.Error(this, "Could not lock folder", ex.Message);
        }
    }

    private async void OnOpenFolder(object? sender, RoutedEventArgs e)
    {
        if (_engine is null) return;
        try
        {
            _engine.OpenFolder();
            RefreshFolderUi();
            UnlockedInfo.Text = "Folder restored to disk. Click \u201CLock folder\u201D when you're done to secure it again.";
        }
        catch (Exception ex)
        {
            await Dialog.Error(this, "Could not open folder", ex.Message);
        }
    }

    private async void OnForgetFolder(object? sender, RoutedEventArgs e)
    {
        if (_engine is null) return;
        var ok = await Dialog.Confirm(this, "Stop protecting this folder?",
            "This clears it from the vault and deletes the encrypted copy. The folder stays on disk exactly as it is now. Continue?");
        if (!ok) return;
        try
        {
            _engine.ForgetFolder();
            RefreshFolderUi();
            UnlockedInfo.Text = "No longer protecting a folder.";
        }
        catch (Exception ex)
        {
            await Dialog.Error(this, "Error", ex.Message);
        }
    }

    private async void OnLockNow(object? sender, RoutedEventArgs e)
    {
        if (_engine is null) return;

        var path = _engine.GetProtectedFolderPath();
        bool locked = _engine.IsFolderLocked();
        if (!string.IsNullOrEmpty(path) && !locked && Directory.Exists(path))
        {
            var alsoLock = await Dialog.Confirm(this, "Folder is open",
                "The protected folder is currently readable on disk. Re-encrypt (lock) it before locking the vault?");
            if (alsoLock)
            {
                try { _engine.LockFolder(path); }
                catch (Exception ex) { await Dialog.Error(this, "Could not lock folder", ex.Message); return; }
            }
        }

        try { _engine.Lock(); } catch { /* ignore */ }
    }

    private async void OnSelfTest(object? sender, RoutedEventArgs e)
    {
        try { await Dialog.Info(this, "Security self-test", SelfTest.Run()); }
        catch (Exception ex) { await Dialog.Error(this, "Self-test failed", ex.Message); }
    }

    // Auto-lock: re-secure an open folder on idle timeout, then drop the key.
    private void AutoLockElapsed()
    {
        try
        {
            var path = _engine?.GetProtectedFolderPath();
            if (_engine is not null && !_engine.IsFolderLocked()
                && !string.IsNullOrEmpty(path) && Directory.Exists(path))
                _engine.LockFolder(path);
        }
        catch { /* best-effort; still drop the key */ }
        try { _engine?.Lock(); } catch { /* ignore */ }
    }

    private async Task OfferVaultReset(string reason)
    {
        var reset = await Dialog.Confirm(this, "Vault problem",
            reason + "\n\nReset the vault? This permanently deletes the encrypted data so you can start over.");
        if (reset) { try { _engine?.Wipe(); } catch { /* best-effort */ } }
        ShowLockedOrSetup();
    }
}
