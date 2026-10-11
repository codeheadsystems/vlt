# vlt PRFAQ: A Password Manager You Own

Oct 10, 2026 · @Ned Wolpert

## Press release

### vlt: the password manager that lives in your own S3 bucket

*Your passwords, encrypted on your devices, stored in a bucket only you control, for less than a dollar a year. The ergonomics of pass, on your phone and in Firefox too.*

**\[CITY\], \[LAUNCH DATE\].** Today Ned released `vlt`, an open-source password manager for people who want to own their vault outright. `vlt` encrypts every entry on the device, stores only ciphertext in a private Amazon S3 bucket or on a self-hosted RustFS server, and works from the Linux and FreeBSD command line, on Android, and in Firefox.

Hosted password managers are convenient until the pricing changes, the free tier shrinks, or the company is acquired. Self-hosting usually means running a server, patching it and backing it up. The classic Unix answer, pass, is beautifully simple but leaks entry names, leans on GPG, and needs a git server and third-party apps to reach a phone or browser.

`vlt` keeps what makes pass great and removes the server. Each password is its own encrypted entry in a familiar tree (`Email/zx2c4.com`), in pass's plain-text format: password on the first line, details below. `vlt show -c` copies a password and clears the clipboard 45 seconds later. `vlt generate`, `vlt edit` and tab completion behave the way pass users expect. The difference is underneath: entry names are encrypted too, sync runs through S3 with automatic version history, and every client shares one crypto core written in Rust.

> "I wanted pass on my phone and in my browser without trusting anyone's server or anyone's pricing page," said Ned, the author. "`vlt` costs me cents a year, and if I ever want out, one command writes a standard pass store."

Setup takes about ten minutes: point it at a bucket in your AWS account or at your own RustFS server, run `vlt init`, and import a Bitwarden or pass export. `vlt init` prints an emergency kit to keep in a drawer. Enroll a phone by creating an AWS key for it with the commands `vlt` prints, then scanning a QR code; unlock it with a fingerprint after that. In Firefox, the extension fills logins on the matching site with one click.

`vlt` is available today as source on GitHub, with CLI builds for Linux and FreeBSD and an Android APK.

## Customer FAQ

**What happens if AWS, or someone at AWS, reads my bucket?** They see opaque object IDs, sizes rounded to 512 bytes, and timestamps. Entry names, URLs, usernames and passwords are encrypted on your device before upload.

**What if my phone is stolen?** The thief gets the phone's AWS key and an encrypted local copy. Unlocking still needs your fingerprint or master password plus the vault's secret key. Delete the phone's AWS key with the IAM commands `vlt` prints (vlt never holds admin credentials), then revoke its enrollment from any other device, and the vault key rotates.

**What if I forget my master password?** There is no reset; that is the point of zero-knowledge. Any still-enrolled device that unlocks without it (a phone with a fingerprint, or a computer with an OS keyring) can set a new one. The emergency kit plus an enrolled device also works. Losing every device and the password means losing the vault, so keep an encrypted export offline.

**How much does it cost?** S3 storage and requests for a personal vault come to cents per year at current S3 prices. There is no subscription, and a self-hosted RustFS server costs nothing beyond your own hardware.

**Can I use my existing pass tools?** The CLI verbs and entry format match pass, so muscle memory and most scripts carry over. pass itself cannot read the S3 store directly, but `vlt export --pass` writes a real `~/.password-store` any time.

**Does it work offline?** Yes. Every client keeps an encrypted local mirror. Reads work offline; edits queue and sync later.

**Do I need AWS?** No. Any S3-compatible server works, and RustFS is the supported self-hosted option. Both RustFS setups are supported. On a single disk, vlt keeps the revision history itself. On four or more disks with erasure coding, RustFS also versions every object, so history is kept twice.

**Can my partner or family share my vault?** No. vlt is a single-user password manager by design; there are no shared folders.

**What happens when two devices edit at once?** Edits to different entries merge automatically. Two edits to the same entry keep the one further along its edit history and save the other as a `.conflict` copy, so nothing is lost.

**Does it support TOTP codes and passkeys?** TOTP, yes, from an `otpauth://` line in the entry, like pass-otp. Passkey storage and unlocking with a hardware security key are planned for a later release.

**Can I get my data out?** Always. Export to a pass store, JSON, CSV, or an encrypted backup file. Version history lives in your bucket, not in `vlt`.

## Internal FAQ

**Why build this instead of self-hosting Vaultwarden or just using pass?** Vaultwarden removes the pricing risk but adds a server to run, patch and back up, and still depends on Bitwarden's clients. pass has no server but leaks entry names, depends on GPG on every device, and its phone and browser story is a patchwork of separate community projects. `vlt` targets the gap: no server, names encrypted, one core across all clients. Bitwarden's own self-hosted and export options remain the fallback if this stalls.

**What is the biggest risk?** A crypto or key-handling bug that leaks or loses the vault. Mitigations: write the spec before code, use only standard primitives through a well-reviewed library, test vectors shared by all clients, an encrypted offline export, and running alongside Bitwarden until each phase's exit criteria are met.

**Second biggest risk?** Scope. Four clients is a lot for one person. The CLI alone already beats pass for me; Android is required to retire Bitwarden; Firefox and the desktop app can slip without blocking the switch.

**Why S3 and not DynamoDB?** Both cost effectively nothing at this scale. S3 adds free version history, lifecycle retention, conditional writes for safe concurrency, and maps directly onto pass's file-per-entry model. DynamoDB would need its own history and backup design.

**Why Rust?** One core has to run natively on Linux and FreeBSD, inside an Android app, and in a Firefox extension. Rust compiles to a native FreeBSD binary with no runtime to ship, binds to Kotlin on Android through UniFFI, and builds to WASM for the browser. The RustCrypto and libsodium ecosystems cover every primitive the spec needs.

**Why support RustFS as well as AWS?** It keeps the exit door open in both directions: the vault can live entirely on hardware I own, with no cloud account at all. The cost is one more backend to test, and RustFS only versions objects when run with erasure coding, which is why vlt keeps its own revision history.

**How do clients authenticate to S3 without a server?** One IAM access key per device, scoped to the bucket prefix, with no right to delete object versions or change bucket policy. A stolen key can add junk versions but not decrypt or erase history. Revocation happens in IAM, or in RustFS's own users and policies when self-hosting. Short-lived credentials (STS or IAM Roles Anywhere) are a later hardening option.

**Why not keep GPG, like pass?** GPG is awkward on Android and in a browser extension, and its key management is the part of pass most people struggle with. Decision: no GPG support at all; pass interop is import and export only. Hardware security keys arrive in a later revision through FIDO2, not GPG.

**How do we know it is safe enough to move real passwords into?** Exit criteria per phase: two weeks of daily use alongside Bitwarden, a round-trip import and export diff with no losses, a restore drill from the emergency kit on a clean machine, and an outside review of the crypto spec.

**What does success look like in a year?** Bitwarden account closed, all daily logins served by `vlt` on CLI, phone and Firefox, total AWS bill under $1, and at least one successful restore drill.
