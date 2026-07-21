using System;
using System.IO;
using System.Security.Cryptography;

namespace AppLockVault;

/// <summary>
/// Small, auditable cryptographic core. Everything security-critical lives here so it can be
/// reviewed in one place.
/// </summary>
public static class SecureCrypto
{
    public const int KeySize = 32;    // 256-bit keys
    public const int NonceSize = 12;  // AES-GCM standard nonce length
    public const int TagSize = 16;    // 128-bit authentication tag
    public const int SaltSize = 16;

    // ---- CSPRNG ----
    public static byte[] RandomBytes(int n) => RandomNumberGenerator.GetBytes(n);

    // ---- Key derivation ----
    // DEFAULT = PBKDF2-HMAC-SHA256 so this project builds with ZERO external NuGet packages.
    // PRODUCTION = swap the body for Argon2id (memory-hard). See README "Hardening" for the
    // 4-line drop-in. Keep the signature identical and nothing else changes.
    public static byte[] DeriveKey(byte[] password, byte[] salt, KdfParams p)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, p.Iterations, HashAlgorithmName.SHA256, KeySize);
    }

    // ---- AES-256-GCM (authenticated encryption) ----
    public static (byte[] nonce, byte[] cipher, byte[] tag) Encrypt(byte[] key, byte[] plaintext, byte[]? aad = null)
    {
        var nonce = RandomBytes(NonceSize);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, cipher, tag, aad);
        return (nonce, cipher, tag);
    }

    /// Throws AuthenticationTagMismatchException if the key is wrong or the data was tampered with.
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] cipher, byte[] tag, byte[]? aad = null)
    {
        var plaintext = new byte[cipher.Length];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, cipher, tag, plaintext, aad);
        return plaintext;
    }

    // ---- Constant-time comparison (defeats timing attacks on verifiers) ----
    public static bool FixedEquals(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);

    // ---- Zeroization of in-memory secrets ----
    public static void Zero(byte[]? b)
    {
        if (b is not null) CryptographicOperations.ZeroMemory(b);
    }

    // ---- Best-effort secure delete ----
    // IMPORTANT: On SSD/flash + copy-on-write filesystems, overwriting does NOT guarantee the old
    // blocks are erased (wear-levelling). Real security comes from CRYPTO-SHREDDING — destroying the
    // key so the ciphertext can never be decrypted. Treat this overwrite as defence-in-depth only.
    public static void SecureDelete(string path, int passes = 2)
    {
        try
        {
            if (!File.Exists(path)) return;
            long len = new FileInfo(path).Length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                var buf = new byte[81920];
                for (int pass = 0; pass < passes; pass++)
                {
                    fs.Position = 0;
                    long written = 0;
                    while (written < len)
                    {
                        RandomNumberGenerator.Fill(buf);
                        int chunk = (int)Math.Min(buf.Length, len - written);
                        fs.Write(buf, 0, chunk);
                        written += chunk;
                    }
                    fs.Flush(true);
                }
                fs.SetLength(0);
                fs.Flush(true);
            }
            File.Delete(path);
        }
        catch { /* deletion is best-effort; never throw from a wipe path */ }
    }

    // Best-effort secure delete of a whole directory tree (same SSD caveat as SecureDelete).
    public static void SecureDeleteDirectory(string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return;
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                SecureDelete(file);
            Directory.Delete(dir, recursive: true);
        }
        catch { /* best-effort */ }
    }
}
