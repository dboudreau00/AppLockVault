# AppLock Vault

A password-gated protection layer for an application or data set. Protected content lives
**encrypted at rest** (AES-256-GCM); a master password unlocks it, a duress password destroys it,
and an idle timer re-locks it. Built on **Avalonia** (Windows / macOS / Linux) with a sleek dark
theme. This is a working, buildable **foundation** — not a finished commercial product. Read the
limits section before you rely on it.

## How it works (envelope encryption)

```
password ──KDF──► KEK (key-encryption-key)
random DEK (data key) ──encrypts──► your app/data  →  payload.enc
DEK ──wrapped by KEK──► stored in vault.json
```

- **Unlock** = re-derive the KEK from the password and unwrap the DEK. The AES-GCM authentication
  tag *is* the "is this the right password?" check — there's no stored password.
- **Duress** = a separate password whose only stored form is a hash used to *detect* it. Entering
  it (a configurable number of times) triggers a **crypto-shred**.
- **Wipe** = delete `vault.json`, which holds the wrapped DEK. Without it, `payload.enc` can never
  be decrypted. That is the real erase; overwriting bytes is only defence-in-depth.

## Locking a folder

**Lock folder** encrypts the folder's contents into the vault **and then securely removes the
original from disk**. While locked, the folder does not exist in its original location — only
ciphertext remains — so an administrator (or anyone who images the drive) sees encrypted bytes, not
your files. **Open folder** decrypts and restores it after you enter your password.

This is the crucial difference from permission/ACL-based "folder lockers": an administrator can take
ownership and reset ACLs, so access control never stops a privileged user. Only encryption makes the
data itself unreadable. Locking is verified before anything is deleted: the encrypted copy is
decrypted, extracted to a temp area, and checked byte-for-byte (every file, by size and SHA-256)
against the original — the folder is removed only if that matches exactly. Empty folders and
cloud/online-only files are refused, and the live payload is replaced only after the check passes.
So a failed or incomplete lock cannot lose your data. Auto-lock and duress-wipe both re-secure or
destroy an open folder.

Honest limits:
- While a folder is **open** it is plaintext on disk and readable by anyone with access — that is
  unavoidable, since the app can't both hand you the files and keep them unreadable.
- Securely erasing the *pre-existing* plaintext is best-effort and unreliable on SSDs
  (wear-levelling). Run full-disk encryption (BitLocker / FileVault) underneath for real at-rest
  protection of any remnants.
- The current build loads the whole folder into memory to encrypt it, so it suits modestly-sized
  folders; streaming is a future improvement.
- This is a container/vault, not a kernel-level real-time lock — protection comes from the data
  being encrypted at rest, not from intercepting file access.

## Build & run

Requires the .NET 8 SDK. NuGet restore needs network access the first time.

```
dotnet restore
dotnet run
```

Unlock, then click **Run security self-test** to verify the full lifecycle
(setup → wrong password → master unlock → roundtrip → lock → duress wipe) at runtime.

Ship as a self-contained native binary (also the biggest anti-reverse-engineering win — no IL to
decompile):

```
dotnet publish -c Release -r win-x64   /p:PublishAot=true
dotnet publish -c Release -r linux-x64 /p:PublishAot=true
dotnet publish -c Release -r osx-arm64 /p:PublishAot=true
```

## What this genuinely delivers vs. what it can't

**Delivers**
- App-lock behaviour with a master password and AES-256-GCM.
- A duress password that securely destroys the vault (configurable trigger count), and **only** on
  the accurate duress password — wrong guesses never wipe.
- Idle auto-lock that drops keys from memory (configurable seconds).
- Content encrypted at rest, so a copied vault file is useless ciphertext. This is the real answer
  to "prevent imaging/copying while locked."

**Can't, on a general-purpose OS — be aware:**
- **You cannot stop a copy.** An admin can copy any file. Protection comes from the copy being
  encrypted, not from blocking the copy. A kernel driver can *hinder* reads but is still defeatable
  by anyone with admin.
- **You cannot make reverse-engineering impossible** — only expensive (see Hardening).
- **Overwrite-wipe is unreliable on SSDs** (wear-levelling). Security rests on key destruction.
- **Duress-wipe does not help against an adversary who already exfiltrated the vault** — they wipe
  nothing on *your* machine's copy. The encryption is what protects the exfiltrated copy.
- .NET strings are immutable, so the password *string* from the textbox can't be zeroed. Derived
  keys and byte buffers are zeroed.

## Error handling

- Corrupt/tampered vault files are validated on load and surfaced via a typed `VaultException`; the
  UI offers a one-click reset instead of crashing.
- Vault and payload are written to a temp file then atomically moved; `Setup` rolls both back on
  failure, so an interrupted write can't brick the vault.
- Counter persistence is best-effort — a locked/read-only file can't break the auth decision (see
  the comment in `ProtectionEngine.TryUnlock` for the TPM-monotonic-counter alternative).
- Every UI action has a try/catch; the temporary plaintext archive from "Protect a folder" is
  always securely deleted and its in-memory bytes zeroed, even on failure.

## Hardening for production

1. **Use Argon2id, not PBKDF2** (memory-hard = far more resistant to GPU cracking). Add the
   `Konscious.Security.Cryptography.Argon2` NuGet package and replace the body of
   `SecureCrypto.DeriveKey`:

   ```csharp
   using Konscious.Security.Cryptography;
   public static byte[] DeriveKey(byte[] password, byte[] salt, KdfParams p)
   {
       using var a = new Argon2id(password)
       {
           Salt = salt,
           Iterations = p.Iterations,            // ~4
           MemorySize = p.MemoryKiB,             // e.g. 131072 (128 MiB)
           DegreeOfParallelism = p.Parallelism   // e.g. 2
       };
       return a.GetBytes(KeySize);
   }
   ```
   Then set `KdfParams { Type="argon2id", Iterations=4, MemoryKiB=131072, Parallelism=2 }` in
   `ProtectionEngine.Setup`.

2. **Ship native (NativeAOT)** — see the publish commands above — plus an obfuscator, and a
   commercial packer (VMProtect/Themida) for high-value targets.

3. **Sign the binary** (Authenticode on Windows, codesign/notarize on macOS) so tampering is
   detectable, and consider running from a RAM disk so the temporary plaintext archive created
   during "Protect a folder" never touches disk.

4. **Launching a protected executable** currently means decrypting to a locked-down temp location,
   launching, then wiping on lock. In-memory execution avoids the plaintext-on-disk window but is
   OS-specific and complex — a good next step if you need it.

## Files

| File | Role |
|------|------|
| `SecureCrypto.cs` | KDF, AES-256-GCM, RNG, zeroization, secure delete |
| `ProtectionEngine.cs` | Setup, unlock, duress detection, crypto-shred wipe, payload encryption |
| `VaultModels.cs` | On-disk vault format, config, KDF params, `VaultException` |
| `AutoLockService.cs` | Idle auto-lock timer (Avalonia dispatcher) |
| `AntiTamper.cs` | Cross-platform anti-debug checks (speed bump only) |
| `SelfTest.cs` | Runtime verification of the lifecycle |
| `App.axaml` / `App.axaml.cs` | Avalonia app + sleek dark theme |
| `MainWindow.axaml` / `.axaml.cs` | The GUI (setup / locked / unlocked) |
| `Dialog.cs` | Themed modal dialogs (Avalonia has no built-in message box) |
| `Program.cs` | Avalonia entry point |
