using System;

namespace AppLockVault;

public enum UnlockResult
{
    Unlocked,
    Denied,        // wrong password (also returned for sub-threshold duress entries, on purpose)
    Wiped,         // correct duress password reached its trigger count -> vault destroyed
    LockedOut,     // too many wrong attempts (lock only, NOT a wipe)
    NotProvisioned
}

/// Parameters for key derivation. PBKDF2 uses Iterations only. Argon2id (production) also uses
/// MemoryKiB + Parallelism — see README.
public sealed class KdfParams
{
    public string Type { get; set; } = "pbkdf2-sha256";
    public int Iterations { get; set; } = 600_000; // PBKDF2-SHA256 baseline; Argon2id uses ~3-4
    public int MemoryKiB { get; set; } = 0;         // Argon2id only (e.g. 131072 = 128 MiB)
    public int Parallelism { get; set; } = 0;       // Argon2id only
}

public sealed class VaultConfig
{
    public int AutoLockSeconds { get; set; } = 300;   // idle seconds before auto-lock; 0 = disabled
    public int DuressTriggerCount { get; set; } = 1;  // correct-duress entries required before wipe fires
    public int MaxFailedAttempts { get; set; } = 10;  // wrong attempts before lock-out; 0 = disabled
}

/// An AES-GCM encrypted blob. Stored as base64 strings in JSON. Contains no plaintext secret.
public sealed class SealedBlob
{
    public string Nonce { get; set; } = "";
    public string Cipher { get; set; } = "";
    public string Tag { get; set; } = "";
}

/// The on-disk vault descriptor (vault.json). Holds ONLY salts, ciphertext and a hash —
/// never a plaintext password or key. Deleting this file crypto-shreds the wrapped data key.
public sealed class VaultFile
{
    public int Version { get; set; } = 1;
    public string MasterSalt { get; set; } = "";
    public string DuressSalt { get; set; } = "";
    public string DuressVerifier { get; set; } = ""; // KDF(duress pw) — used only to DETECT duress
    public SealedBlob WrappedDek { get; set; } = new(); // data key encrypted under master-derived key
    public KdfParams Kdf { get; set; } = new();
    public VaultConfig Config { get; set; } = new();
    public int DuressCounter { get; set; } = 0;
    public int FailedCounter { get; set; } = 0;

    /// Absolute path of the folder this vault protects (null if none).
    public string? ProtectedFolderPath { get; set; }

    /// True when the folder's contents live ONLY in the encrypted payload (original removed from
    /// disk). This is the authoritative state — never infer "locked" from whether the path exists
    /// on disk, since a partial delete can leave a stray directory behind.
    public bool FolderLocked { get; set; }
}

/// Thrown for unrecoverable vault problems: a corrupt/tampered file, an IO/permission failure, or
/// a partial write. These are distinct from normal authentication outcomes, which are returned as
/// <see cref="UnlockResult"/> values (never thrown).
public sealed class VaultException : Exception
{
    public VaultException(string message) : base(message) { }
    public VaultException(string message, Exception inner) : base(message, inner) { }
}
