# AppLock Vault

An educational, cross-platform (Windows/macOS/Linux) app-locker built in C# + Avalonia. It password-
protects a folder by **encrypting its contents (AES-256-GCM) and removing the plaintext original**, so
while "locked" the data exists only as ciphertext — unreadable even to an administrator. A duress
password crypto-shreds the vault; an idle timer re-locks.

> **Status / disclaimer.** This is a study project, not audited production software. An earlier
> version had a serious bug: it could delete a folder while storing an **empty** encrypted copy
> (data loss). That is fixed here — see "Safety" below — but treat the code as a learning artifact,
> test on **throwaway folders**, and keep full-disk encryption (BitLocker/FileVault) on underneath.

## Run it (three ways)

- **Recovery tool only** → open `AppLockVault-Recover/AppLockVault.Recover.sln` (or `dotnet run` in
  that folder). Read-only on the vault; decrypts `payload.enc` back into a `.zip`. Works offline.
- **App only** → open `AppLockVault/AppLockVault.sln` (or `dotnet run` in that folder). First run
  needs internet to restore the Avalonia NuGet packages.
- **Everything** → open `AppLockVault-Project.sln` here (loads both projects).

No `.sln` is actually required for `dotnet run` — install the .NET 8 SDK and run from the folder —
but the solution files are included so double-clicking works. After unlocking, click
**Run security self-test** to exercise the whole lifecycle (including a folder lock→open round-trip).

## Safety (what prevents the earlier data-loss bug)

- **Verify-before-delete.** Locking archives the folder, encrypts it, then *decrypts that copy,
  extracts it to a temp area, and compares every file byte-for-byte (size + SHA-256) to the
  original*. The original is deleted **only** if the copy matches exactly.
- **Live payload replaced only after the check passes** — a failed lock can't overwrite a good copy.
- **Empty folders and cloud/online-only files (OneDrive Files On-Demand) are refused** — those were
  the conditions that produced an empty payload.
- **System / known folders are refused** (Screenshots, Camera Roll, Downloads, Desktop, Documents,
  Pictures, OneDrive/reparse-point folders, drive roots, Program Files, Windows).
- **Locked/open is an explicit flag**, never inferred from the disk; **restore extracts on top of**
  any leftover directory; **you can't overwrite an already-locked folder**.

## Honest limits

- While a folder is **open** it is plaintext on disk. Protection applies while it's **locked**.
- Securely erasing the *pre-existing* plaintext is best-effort on SSDs — keep BitLocker/FileVault on.
- One protected folder at a time; the whole folder is loaded into memory to encrypt (fine for modest
  sizes; streaming is future work).
- Crypto is PBKDF2-SHA256 by default; Argon2id is the recommended production swap (see
  `AppLockVault/README.md`). This is an encrypted container, not a kernel-level real-time lock.
- **No password recovery.** The master password is the only key; lose it and the encrypted copy is
  unrecoverable by design.

See `AppLockVault/README.md` for the full security model and the Argon2id / NativeAOT hardening notes.
