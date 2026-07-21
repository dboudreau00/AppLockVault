using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AppLockVault.Recover;

// Recovery + diagnostic tool for AppLock Vault. READ-ONLY on the vault (never deletes/modifies it).
// The password is shown as you type and you can retry as many times as you like.
//
//   dotnet run                                (uses %LOCALAPPDATA%\AppLockVault)
//   dotnet run -- "C:\path\to\AppLockVault"   (if your vault is elsewhere)
internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            string vaultDir = args.Length >= 1
                ? args[0]
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AppLockVault");
            string vaultPath = Path.Combine(vaultDir, "vault.json");
            string payloadPath = Path.Combine(vaultDir, "payload.enc");

            Console.WriteLine("AppLock Vault - recovery / diagnostic");
            Console.WriteLine("Vault folder  : " + vaultDir);
            if (!File.Exists(vaultPath))
            {
                Console.WriteLine("ERROR: vault.json not found there. Pass the folder explicitly:");
                Console.WriteLine("  dotnet run -- \"C:\\Users\\<you>\\AppData\\Local\\AppLockVault\"");
                return 2;
            }
            if (!File.Exists(payloadPath)) { Console.WriteLine("ERROR: payload.enc not found."); return 2; }

            // Jackpot check: an un-encrypted leftover copy of your data.
            foreach (var f in Directory.EnumerateFiles(vaultDir))
            {
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (ext == ".zip" || ext == ".tmp")
                    Console.WriteLine("NOTE: leftover file (could be an UNENCRYPTED copy of your data!): " + f);
            }

            using var doc = JsonDocument.Parse(File.ReadAllText(vaultPath));
            var root = doc.RootElement;
            byte[] masterSalt = Convert.FromBase64String(root.GetProperty("MasterSalt").GetString()!);
            var wrapped = root.GetProperty("WrappedDek");
            byte[] wNonce = Convert.FromBase64String(wrapped.GetProperty("Nonce").GetString()!);
            byte[] wCipher = Convert.FromBase64String(wrapped.GetProperty("Cipher").GetString()!);
            byte[] wTag = Convert.FromBase64String(wrapped.GetProperty("Tag").GetString()!);
            int iterations = 600_000;
            if (root.TryGetProperty("Kdf", out var kdf) && kdf.TryGetProperty("Iterations", out var it)) iterations = it.GetInt32();

            Console.WriteLine($"payload.enc   : {new FileInfo(payloadPath).Length} bytes  (large = your data is in here)");
            Console.WriteLine($"KDF iterations: {iterations}");
            if (root.TryGetProperty("ProtectedFolderPath", out var pfp) && pfp.ValueKind == JsonValueKind.String)
                Console.WriteLine("Locked folder : " + pfp.GetString());
            if (root.TryGetProperty("FolderLocked", out var fl)) Console.WriteLine("FolderLocked  : " + fl.GetRawText());
            Console.WriteLine();
            Console.WriteLine("Type your master password and press Enter (shown so you can verify it).");
            Console.WriteLine("It also auto-tries trimmed/space variants. Type  q  to quit.");
            Console.WriteLine();

            while (true)
            {
                Console.Write("Password: ");
                string? entry = Console.ReadLine();
                if (entry is null || entry.Trim().Equals("q", StringComparison.OrdinalIgnoreCase)) { Console.WriteLine("Bye."); return 0; }

                Console.WriteLine($"(received {Encoding.UTF8.GetByteCount(entry)} bytes)");

                bool matched = false;
                foreach (var candidate in Variants(entry))
                {
                    if (TryUnwrap(candidate, masterSalt, iterations, wNonce, wCipher, wTag, out var dek))
                    {
                        if (!candidate.Equals(entry, StringComparison.Ordinal))
                            Console.WriteLine("(matched a trimmed/space variant of what you typed)");
                        return Decrypt(payloadPath, dek!);
                    }
                }
                if (!matched)
                    Console.WriteLine("No match. Check Caps Lock + keyboard layout, and type it exactly as you set it.\n");
            }
        }
        catch (Exception ex) { Console.WriteLine("Unexpected error: " + ex.Message); return 1; }
    }

    private static IEnumerable<string> Variants(string s)
    {
        var list = new List<string> { s };
        void Add(string v) { if (!list.Contains(v)) list.Add(v); }
        Add(s.Trim());
        Add(s.TrimEnd());
        Add(s.TrimStart());
        Add(s + " ");
        return list;
    }

    private static bool TryUnwrap(string pw, byte[] salt, int iter, byte[] n, byte[] c, byte[] t, out byte[]? dek)
    {
        dek = null;
        try
        {
            byte[] kek = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(pw), salt, iter, HashAlgorithmName.SHA256, 32);
            var buf = new byte[c.Length];
            using var gcm = new AesGcm(kek, 16);
            gcm.Decrypt(n, c, t, buf);
            dek = buf;
            return true;
        }
        catch (AuthenticationTagMismatchException) { return false; }
    }

    private static int Decrypt(string payloadPath, byte[] dek)
    {
        byte[] blob = File.ReadAllBytes(payloadPath);
        if (blob.Length < 28) { Console.WriteLine("payload.enc is too small to be valid."); return 4; }
        byte[] pn = blob[..12], pt = blob[12..28], pc = blob[28..];
        byte[] zip = new byte[pc.Length];
        using (var gcm = new AesGcm(dek, 16)) gcm.Decrypt(pn, pt, pc, zip);

        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrEmpty(desktop)) desktop = Directory.GetCurrentDirectory();
        string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        string zipOut = Path.Combine(desktop, $"AppLockVault-recovered-{stamp}.zip");
        File.WriteAllBytes(zipOut, zip);
        Console.WriteLine();
        Console.WriteLine("SUCCESS! Recovered zip : " + zipOut);
        try
        {
            string dir = Path.Combine(desktop, $"AppLockVault-recovered-{stamp}");
            ZipFile.ExtractToDirectory(zipOut, dir);
            Console.WriteLine("Extracted folder      : " + dir);
        }
        catch (Exception ex) { Console.WriteLine("(auto-extract skipped: " + ex.Message + " - right-click the zip, Extract All)"); }
        return 0;
    }
}
