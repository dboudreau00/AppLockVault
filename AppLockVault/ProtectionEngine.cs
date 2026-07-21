using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AppLockVault;

/// <summary>
/// Envelope encryption: password --KDF--> KEK; a random DEK encrypts the folder's contents
/// (payload.enc); the DEK is wrapped by the KEK in vault.json.
///
/// SAFETY RULE FOR LOCKING: the original folder is deleted ONLY after the encrypted copy has been
/// decrypted, extracted to a temp area, and confirmed byte-for-byte identical to the original
/// (every file matched by size + SHA-256). The live payload is replaced only after that check
/// passes. If anything is empty, cloud-only, or fails to round-trip, nothing is deleted or replaced.
///
/// Normal auth outcomes return UnlockResult. Unrecoverable problems throw VaultException.
/// </summary>
public sealed class ProtectionEngine : IDisposable
{
    private readonly string _vaultDir;
    private readonly string _vaultPath;
    private readonly string _payloadPath;

    private byte[]? _dek;
    public bool IsUnlocked => _dek is not null;
    public bool IsProvisioned => File.Exists(_vaultPath);

    public event Action? Locked;

    public ProtectionEngine(string vaultDir)
    {
        if (string.IsNullOrWhiteSpace(vaultDir)) throw new ArgumentException("Vault directory required.", nameof(vaultDir));
        _vaultDir = vaultDir;
        try { Directory.CreateDirectory(_vaultDir); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { throw new VaultException("Could not create or access the vault directory.", ex); }
        _vaultPath = Path.Combine(_vaultDir, "vault.json");
        _payloadPath = Path.Combine(_vaultDir, "payload.enc");
    }

    // ---------------- Setup ----------------
    public void Setup(string masterPassword, string duressPassword, VaultConfig config)
    {
        if (IsProvisioned) throw new InvalidOperationException("A vault already exists.");
        if (string.IsNullOrEmpty(masterPassword)) throw new ArgumentException("Master password required.");
        if (string.IsNullOrEmpty(duressPassword)) throw new ArgumentException("Duress password required.");
        if (masterPassword == duressPassword) throw new ArgumentException("Master and duress passwords must differ.");

        byte[]? mpw = null, dpw = null, kek = null, dek = null, duressKey = null;
        try
        {
            var kdf = new KdfParams();
            var masterSalt = SecureCrypto.RandomBytes(SecureCrypto.SaltSize);
            var duressSalt = SecureCrypto.RandomBytes(SecureCrypto.SaltSize);

            mpw = Encoding.UTF8.GetBytes(masterPassword);
            dpw = Encoding.UTF8.GetBytes(duressPassword);

            dek = SecureCrypto.RandomBytes(SecureCrypto.KeySize);
            kek = SecureCrypto.DeriveKey(mpw, masterSalt, kdf);
            duressKey = SecureCrypto.DeriveKey(dpw, duressSalt, kdf);

            var (n, c, t) = SecureCrypto.Encrypt(kek, dek);

            var vf = new VaultFile
            {
                MasterSalt = Convert.ToBase64String(masterSalt),
                DuressSalt = Convert.ToBase64String(duressSalt),
                DuressVerifier = Convert.ToBase64String(duressKey),
                WrappedDek = new SealedBlob
                {
                    Nonce = Convert.ToBase64String(n),
                    Cipher = Convert.ToBase64String(c),
                    Tag = Convert.ToBase64String(t)
                },
                Kdf = kdf,
                Config = config ?? new VaultConfig()
            };

            SaveVault(vf);
            ProtectBytesInternal(dek, Array.Empty<byte>());
        }
        catch (Exception ex)
        {
            SecureCrypto.SecureDelete(_vaultPath);
            SecureCrypto.SecureDelete(_payloadPath);
            if (ex is VaultException) throw;
            throw new VaultException("Failed to create the vault: " + ex.Message, ex);
        }
        finally
        {
            SecureCrypto.Zero(mpw); SecureCrypto.Zero(dpw);
            SecureCrypto.Zero(kek); SecureCrypto.Zero(duressKey);
            SecureCrypto.Zero(dek);
        }
    }

    // ---------------- Unlock ----------------
    public UnlockResult TryUnlock(string password)
    {
        if (!IsProvisioned) return UnlockResult.NotProvisioned;

        var vf = LoadVault();
        ValidateVault(vf);

        void PersistBestEffort() { try { SaveVault(vf); } catch (VaultException) { /* ignore */ } }

        byte[]? pw = null, kek = null, dek = null, duressCand = null;
        try
        {
            pw = Encoding.UTF8.GetBytes(password ?? string.Empty);

            kek = SecureCrypto.DeriveKey(pw, Convert.FromBase64String(vf.MasterSalt), vf.Kdf);
            try
            {
                dek = SecureCrypto.Decrypt(
                    kek,
                    Convert.FromBase64String(vf.WrappedDek.Nonce),
                    Convert.FromBase64String(vf.WrappedDek.Cipher),
                    Convert.FromBase64String(vf.WrappedDek.Tag));

                _dek = dek; dek = null;
                vf.FailedCounter = 0; vf.DuressCounter = 0;
                PersistBestEffort();
                return UnlockResult.Unlocked;
            }
            catch (AuthenticationTagMismatchException) { /* wrong master -> fall through */ }
            catch (CryptographicException ex)
            { throw new VaultException("Vault key material failed to decrypt (corrupt or tampered).", ex); }

            duressCand = SecureCrypto.DeriveKey(pw, Convert.FromBase64String(vf.DuressSalt), vf.Kdf);
            if (SecureCrypto.FixedEquals(duressCand, Convert.FromBase64String(vf.DuressVerifier)))
            {
                vf.DuressCounter++;
                if (vf.DuressCounter >= Math.Max(1, vf.Config.DuressTriggerCount)) { Wipe(); return UnlockResult.Wiped; }
                PersistBestEffort();
                return UnlockResult.Denied;
            }

            vf.FailedCounter++;
            bool lockedOut = vf.Config.MaxFailedAttempts > 0 && vf.FailedCounter >= vf.Config.MaxFailedAttempts;
            PersistBestEffort();
            return lockedOut ? UnlockResult.LockedOut : UnlockResult.Denied;
        }
        catch (FormatException ex)
        { throw new VaultException("The vault file is corrupt (invalid encoding).", ex); }
        finally
        {
            SecureCrypto.Zero(pw); SecureCrypto.Zero(kek);
            SecureCrypto.Zero(dek); SecureCrypto.Zero(duressCand);
        }
    }

    public void Lock()
    {
        SecureCrypto.Zero(_dek);
        _dek = null;
        RaiseLocked();
    }

    // ---------------- Folder state ----------------
    public string? GetProtectedFolderPath()
    {
        try { return IsProvisioned ? LoadVault().ProtectedFolderPath : null; }
        catch (VaultException) { return null; }
    }

    public bool IsFolderLocked()
    {
        try { return IsProvisioned && LoadVault().FolderLocked; }
        catch (VaultException) { return false; }
    }

    // ---------------- Lock a folder (verify-before-delete) ----------------
    public void LockFolder(string sourceDir)
    {
        if (!IsUnlocked) throw new InvalidOperationException("Unlock before locking a folder.");
        if (string.IsNullOrWhiteSpace(sourceDir) || !Directory.Exists(sourceDir))
            throw new VaultException("Folder not found: " + sourceDir);

        var full = Path.GetFullPath(sourceDir);

        var reason = RiskyFolderReason(full);
        if (reason is not null)
            throw new VaultException($"For safety this build won't lock {reason}:\n{full}\n\nUse a normal folder you created for this.");

        var vaultFull = WithSep(Path.GetFullPath(_vaultDir));
        if (vaultFull.StartsWith(WithSep(full), StringComparison.OrdinalIgnoreCase))
            throw new VaultException("That folder contains the vault's own data. Choose a different folder.");

        var existing = LoadVault();
        if (existing.FolderLocked && !string.IsNullOrEmpty(existing.ProtectedFolderPath)
            && !string.Equals(Path.GetFullPath(existing.ProtectedFolderPath!), full, StringComparison.OrdinalIgnoreCase))
            throw new VaultException("A folder is already locked:\n" + existing.ProtectedFolderPath +
                                     "\n\nOpen it first before locking a different one.");

        var files = Directory.GetFiles(full, "*", SearchOption.AllDirectories);
        if (files.Length == 0)
            throw new VaultException("That folder has no files to lock (it's empty). Nothing was changed.");

        var online = OnlineOnlyFile(full);
        if (online is not null)
            throw new VaultException("Some files are cloud/online-only (not fully downloaded), so they can't be locked safely:\n" +
                online + "\n\nIn Explorer, right-click the folder -> \"Always keep on this device\", let it finish, then try again. Nothing was changed.");

        var original = Manifest(full);      // fingerprint the source (path + size + SHA-256)

        var tmpZip = Path.Combine(_vaultDir, "_lock.tmp.zip");
        var payloadTmp = _payloadPath + ".new";
        var verifyZip = Path.Combine(_vaultDir, "_verify.tmp.zip");
        var verifyDir = Path.Combine(_vaultDir, "_verify.tmp");
        byte[]? bytes = null;
        try
        {
            // 1. archive
            if (File.Exists(tmpZip)) File.Delete(tmpZip);
            ZipFile.CreateFromDirectory(full, tmpZip);
            bytes = File.ReadAllBytes(tmpZip);
            if (bytes.Length == 0)
                throw new VaultException("Internal error: the archive came out empty. Nothing was changed.");

            // 2. encrypt to a NEW file; the live payload.enc is untouched until we've verified
            EncryptToFile(_dek!, bytes, payloadTmp);

            // 3. full round-trip verification: decrypt the new file, extract, compare to the original
            var check = DecryptFromFile(_dek!, payloadTmp);
            File.WriteAllBytes(verifyZip, check);
            SecureCrypto.Zero(check);
            if (Directory.Exists(verifyDir)) Directory.Delete(verifyDir, true);
            ZipFile.ExtractToDirectory(verifyZip, verifyDir);
            var restored = Manifest(verifyDir);
            if (!ManifestsMatch(original, restored))
                throw new VaultException("Safety check failed: the encrypted copy did not exactly match the original, so the folder was NOT deleted.");

            // 4. commit: only now replace the live payload and record state
            File.Move(payloadTmp, _payloadPath, overwrite: true);
            existing.ProtectedFolderPath = full;
            existing.FolderLocked = true;
            SaveVault(existing);

            // 5. proven recoverable -> remove the plaintext original
            SecureCrypto.SecureDeleteDirectory(full);
        }
        catch (Exception ex) when (ex is not VaultException and not InvalidOperationException)
        {
            throw new VaultException("Could not lock the folder: " + ex.Message, ex);
        }
        finally
        {
            SecureCrypto.Zero(bytes);
            SecureCrypto.SecureDelete(tmpZip);
            SecureCrypto.SecureDelete(verifyZip);
            SecureCrypto.SecureDelete(payloadTmp);   // no-op if already committed
            try { if (Directory.Exists(verifyDir)) Directory.Delete(verifyDir, true); } catch { /* ignore */ }
        }
    }

    // ---------------- Open a folder (decrypt + restore) ----------------
    public void OpenFolder()
    {
        if (!IsUnlocked) throw new InvalidOperationException("Unlock before opening the folder.");
        var vf = LoadVault();
        var dest = vf.ProtectedFolderPath;
        if (string.IsNullOrEmpty(dest)) throw new VaultException("No protected folder is registered.");

        var tmpZip = Path.Combine(_vaultDir, "_open.tmp.zip");
        byte[]? bytes = null;
        try
        {
            bytes = RevealBytes();
            File.WriteAllBytes(tmpZip, bytes);
            Directory.CreateDirectory(dest!);                       // ok if a stray directory remains
            ZipFile.ExtractToDirectory(tmpZip, dest!, overwriteFiles: true);
            vf.FolderLocked = false;
            SaveVault(vf);
        }
        catch (Exception ex) when (ex is not VaultException and not InvalidOperationException)
        { throw new VaultException("Could not open the folder: " + ex.Message, ex); }
        finally
        {
            SecureCrypto.Zero(bytes);
            SecureCrypto.SecureDelete(tmpZip);
        }
    }

    public void ForgetFolder()
    {
        if (!IsUnlocked) throw new InvalidOperationException("Unlock first.");
        var vf = LoadVault();
        if (vf.FolderLocked)
            throw new VaultException("Open the folder first — it's still locked. Forgetting now would strand the encrypted data.");
        vf.ProtectedFolderPath = null;
        vf.FolderLocked = false;
        SaveVault(vf);
        ProtectBytesInternal(_dek!, Array.Empty<byte>());
    }

    // ---------------- Raw payload access ----------------
    public void ProtectBytes(byte[] appBytes)
    {
        if (!IsUnlocked) throw new InvalidOperationException("Unlock before protecting content.");
        if (appBytes is null) throw new ArgumentNullException(nameof(appBytes));
        ProtectBytesInternal(_dek!, appBytes);
    }

    public byte[] RevealBytes()
    {
        if (!IsUnlocked) throw new InvalidOperationException("Unlock before revealing content.");
        if (!File.Exists(_payloadPath)) throw new VaultException("The protected payload is missing.");
        return DecryptFromFile(_dek!, _payloadPath);
    }

    private void ProtectBytesInternal(byte[] dek, byte[] appBytes)
    {
        var tmp = _payloadPath + ".tmp";
        try
        {
            EncryptToFile(dek, appBytes, tmp);
            File.Move(tmp, _payloadPath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            SecureCrypto.SecureDelete(tmp);
            throw new VaultException("Could not write the protected payload.", ex);
        }
    }

    private static void EncryptToFile(byte[] dek, byte[] plaintext, string path)
    {
        var (n, c, t) = SecureCrypto.Encrypt(dek, plaintext);       // layout: [nonce][tag][cipher]
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        fs.Write(n); fs.Write(t); fs.Write(c);
        fs.Flush(true);
    }

    private static byte[] DecryptFromFile(byte[] dek, string path)
    {
        byte[] blob;
        try { blob = File.ReadAllBytes(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { throw new VaultException("Could not read the encrypted data.", ex); }

        int header = SecureCrypto.NonceSize + SecureCrypto.TagSize;
        if (blob.Length < header) throw new VaultException("Encrypted data is corrupt (too short).");
        var nonce = blob[..SecureCrypto.NonceSize];
        var tag = blob[SecureCrypto.NonceSize..header];
        var cipher = blob[header..];
        try { return SecureCrypto.Decrypt(dek, nonce, cipher, tag); }
        catch (CryptographicException ex)
        { throw new VaultException("Encrypted data failed to decrypt (corrupt or tampered).", ex); }
    }

    // ---------------- Wipe (duress) ----------------
    public void Wipe()
    {
        SecureCrypto.Zero(_dek); _dek = null;

        string? folder = null; bool locked = false;
        try { if (File.Exists(_vaultPath)) { var v = LoadVault(); folder = v.ProtectedFolderPath; locked = v.FolderLocked; } }
        catch { /* ignore */ }
        if (!locked && !string.IsNullOrEmpty(folder) && Directory.Exists(folder))
            SecureCrypto.SecureDeleteDirectory(folder!);

        SecureCrypto.SecureDelete(_vaultPath);
        SecureCrypto.SecureDelete(_payloadPath);
        RaiseLocked();
    }

    // ---------------- Verification helpers ----------------
    // Map of relative-path -> (length, SHA-256). Used to prove a locked folder round-trips exactly.
    private static Dictionary<string, (long Len, string Hash)> Manifest(string root)
    {
        var map = new Dictionary<string, (long, string)>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(root, file).Replace('\\', '/');
            long len = new FileInfo(file).Length;
            using var fs = File.OpenRead(file);
            var hash = Convert.ToHexString(SHA256.HashData(fs));
            map[rel] = (len, hash);
        }
        return map;
    }

    private static bool ManifestsMatch(Dictionary<string, (long Len, string Hash)> a,
                                       Dictionary<string, (long Len, string Hash)> b)
    {
        if (a.Count != b.Count) return false;
        foreach (var kv in a)
        {
            if (!b.TryGetValue(kv.Key, out var v)) return false;
            if (v.Len != kv.Value.Len || !string.Equals(v.Hash, kv.Value.Hash, StringComparison.Ordinal)) return false;
        }
        return true;
    }

    // Returns the first cloud/online-only (OneDrive Files On-Demand) file found, else null.
    private static string? OnlineOnlyFile(string root)
    {
        const int RECALL_ON_OPEN = 0x00040000;
        const int RECALL_ON_DATA_ACCESS = 0x00400000;
        try
        {
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                var a = (int)File.GetAttributes(file);
                if ((a & RECALL_ON_OPEN) != 0 || (a & RECALL_ON_DATA_ACCESS) != 0
                    || ((FileAttributes)a).HasFlag(FileAttributes.Offline))
                    return file;
            }
        }
        catch { /* if we can't tell, don't block */ }
        return null;
    }

    // ---------------- Guards ----------------
    private static string WithSep(string p)
        => p.EndsWith(Path.DirectorySeparatorChar) ? p : p + Path.DirectorySeparatorChar;

    private static string? RiskyFolderReason(string full)
    {
        string norm = Path.TrimEndingDirectorySeparator(Path.GetFullPath(full));

        var root = Path.GetPathRoot(norm);
        if (!string.IsNullOrEmpty(root) &&
            string.Equals(norm, Path.TrimEndingDirectorySeparator(root), StringComparison.OrdinalIgnoreCase))
            return "a drive root";

        try
        {
            if (new DirectoryInfo(norm).Attributes.HasFlag(FileAttributes.ReparsePoint))
                return "a redirected or cloud-synced folder (reparse point, e.g. OneDrive)";
        }
        catch { /* ignore */ }

        foreach (var s in new[]
        {
            Environment.SpecialFolder.UserProfile, Environment.SpecialFolder.MyDocuments,
            Environment.SpecialFolder.MyPictures, Environment.SpecialFolder.MyMusic,
            Environment.SpecialFolder.MyVideos, Environment.SpecialFolder.Desktop,
            Environment.SpecialFolder.DesktopDirectory, Environment.SpecialFolder.ApplicationData,
            Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolder.CommonApplicationData,
            Environment.SpecialFolder.Windows, Environment.SpecialFolder.System,
            Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86,
        })
        {
            var p = SafeSpecial(s);
            if (p is not null && string.Equals(norm, Path.TrimEndingDirectorySeparator(p), StringComparison.OrdinalIgnoreCase))
                return "a system or known folder";
        }

        var pics = SafeSpecial(Environment.SpecialFolder.MyPictures);
        if (pics is not null)
            foreach (var sub in new[] { "Screenshots", "Camera Roll", "Saved Pictures" })
                if (string.Equals(norm, Path.TrimEndingDirectorySeparator(Path.Combine(pics, sub)), StringComparison.OrdinalIgnoreCase))
                    return "a Windows known folder (" + sub + ")";

        var profile = SafeSpecial(Environment.SpecialFolder.UserProfile);
        if (profile is not null &&
            string.Equals(norm, Path.TrimEndingDirectorySeparator(Path.Combine(profile, "Downloads")), StringComparison.OrdinalIgnoreCase))
            return "the Downloads folder";

        return null;
    }

    private static string? SafeSpecial(Environment.SpecialFolder f)
    {
        try { var p = Environment.GetFolderPath(f); return string.IsNullOrEmpty(p) ? null : p; }
        catch { return null; }
    }

    // ---------------- Persistence ----------------
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    private void SaveVault(VaultFile vf)
    {
        var tmp = _vaultPath + ".tmp";
        try
        {
            File.WriteAllText(tmp, JsonSerializer.Serialize(vf, JsonOpts));
            File.Move(tmp, _vaultPath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* ignore */ }
            throw new VaultException("Could not save the vault file.", ex);
        }
    }

    private VaultFile LoadVault()
    {
        string json;
        try { json = File.ReadAllText(_vaultPath); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { throw new VaultException("Could not read the vault file.", ex); }

        VaultFile? vf;
        try { vf = JsonSerializer.Deserialize<VaultFile>(json); }
        catch (JsonException ex) { throw new VaultException("The vault file is corrupt (invalid format).", ex); }

        return vf ?? throw new VaultException("The vault file is empty or corrupt.");
    }

    private static void ValidateVault(VaultFile vf)
    {
        try
        {
            var ms = Convert.FromBase64String(vf.MasterSalt);
            var ds = Convert.FromBase64String(vf.DuressSalt);
            var dv = Convert.FromBase64String(vf.DuressVerifier);
            var n = Convert.FromBase64String(vf.WrappedDek.Nonce);
            var c = Convert.FromBase64String(vf.WrappedDek.Cipher);
            var t = Convert.FromBase64String(vf.WrappedDek.Tag);

            if (ms.Length == 0 || ds.Length == 0
                || dv.Length != SecureCrypto.KeySize
                || n.Length != SecureCrypto.NonceSize
                || t.Length != SecureCrypto.TagSize
                || c.Length != SecureCrypto.KeySize)
                throw new VaultException("The vault file is present but its fields are invalid.");
        }
        catch (FormatException ex)
        { throw new VaultException("The vault file is corrupt (invalid encoding).", ex); }
    }

    public VaultConfig LoadConfig()
    {
        if (!IsProvisioned) return new VaultConfig();
        try { return LoadVault().Config; }
        catch (VaultException) { return new VaultConfig(); }
    }

    private void RaiseLocked()
    {
        try { Locked?.Invoke(); }
        catch { /* a UI subscriber must never prevent a lock/wipe */ }
    }

    public void Dispose() => Lock();
}
