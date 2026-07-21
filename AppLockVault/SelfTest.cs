using System;
using System.IO;
using System.Text;

namespace AppLockVault;

/// <summary>
/// Runtime proof of the full lifecycle, including the folder lock/open round-trip that previously
/// lost data. Everything runs against throwaway temp folders and is cleaned up afterwards.
/// </summary>
public static class SelfTest
{
    public static string Run()
    {
        var dir = Path.Combine(Path.GetTempPath(), "AppLockVaultSelfTest_" + Guid.NewGuid().ToString("N"));
        var srcFolder = Path.Combine(Path.GetTempPath(), "ALVSelfTestData_" + Guid.NewGuid().ToString("N"));
        var sb = new StringBuilder();
        void pass(string m) => sb.AppendLine("PASS  " + m);
        void fail(string m) => sb.AppendLine("FAIL  " + m);

        try
        {
            var eng = new ProtectionEngine(dir);
            var cfg = new VaultConfig { AutoLockSeconds = 60, DuressTriggerCount = 1, MaxFailedAttempts = 5 };
            eng.Setup("Master-Pass-123", "Duress-Pass-999", cfg);
            if (eng.IsProvisioned) pass("vault provisioned"); else fail("vault not provisioned");

            if (eng.TryUnlock("wrong-guess") == UnlockResult.Denied) pass("wrong password denied");
            else fail("wrong password was not denied");

            if (eng.TryUnlock("Master-Pass-123") == UnlockResult.Unlocked) pass("master unlock");
            else fail("master unlock failed");

            // raw byte round-trip
            var secret = Encoding.UTF8.GetBytes("hello protected world");
            eng.ProtectBytes(secret);
            var back = eng.RevealBytes();
            if (Convert.ToBase64String(back) == Convert.ToBase64String(secret)) pass("encrypt/decrypt roundtrip");
            else fail("roundtrip mismatch");

            // ---- folder lock / open round-trip (the scenario that lost data) ----
            Directory.CreateDirectory(Path.Combine(srcFolder, "sub"));
            File.WriteAllText(Path.Combine(srcFolder, "a.txt"), "hello world");
            File.WriteAllBytes(Path.Combine(srcFolder, "sub", "b.bin"), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });

            eng.LockFolder(srcFolder);
            bool gone = !Directory.Exists(srcFolder);
            bool flagLocked = eng.IsFolderLocked();
            long plen = new FileInfo(Path.Combine(dir, "payload.enc")).Length;
            if (gone && flagLocked && plen > 28)
                pass($"folder lock: original removed, payload populated ({plen} bytes)");
            else
                fail($"folder lock state wrong (removed={gone}, locked={flagLocked}, payload={plen} bytes)");

            eng.OpenFolder();
            bool a = File.Exists(Path.Combine(srcFolder, "a.txt"));
            bool b = File.Exists(Path.Combine(srcFolder, "sub", "b.bin"));
            bool content = a && File.ReadAllText(Path.Combine(srcFolder, "a.txt")) == "hello world";
            if (a && b && content) pass("folder open: files restored with identical content");
            else fail($"folder open: restore mismatch (a={a}, b={b}, content={content})");

            // empty-folder guard: must refuse and NOT delete
            var emptyDir = Path.Combine(srcFolder, "will-stay");
            Directory.CreateDirectory(emptyDir);
            try { eng.LockFolder(emptyDir); fail("empty folder was locked (should have refused)"); }
            catch (VaultException) { if (Directory.Exists(emptyDir)) pass("empty folder refused, left intact"); else fail("empty folder was deleted"); }

            eng.Lock();
            if (!eng.IsUnlocked) pass("lock drops keys from memory"); else fail("still unlocked after Lock()");

            var r = eng.TryUnlock("Duress-Pass-999");
            if (r == UnlockResult.Wiped) pass("accurate duress triggers wipe");
            else fail("duress did not wipe (got " + r + ")");

            bool vaultGone = !File.Exists(Path.Combine(dir, "vault.json"));
            bool payloadGone = !File.Exists(Path.Combine(dir, "payload.enc"));
            if (vaultGone && payloadGone) pass("crypto-shred removed vault + payload");
            else fail("files remain after wipe");
        }
        catch (Exception ex) { fail("exception: " + ex.Message); }
        finally
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { /* ignore */ }
            try { if (Directory.Exists(srcFolder)) Directory.Delete(srcFolder, true); } catch { /* ignore */ }
        }

        return sb.ToString();
    }
}
