# FL2601 Cipher Tool for Windows
### Passphrase Text Encryption — Windows Port

<p align="center">
  <strong>PBKDF2 + AES-256-GCM, entirely offline</strong>
  <br />
  <strong>Version:</strong> 1.1.0
  <br />
  <a href="https://github.com/sevmorris/FL2601-Windows/releases/latest"><strong>Download Latest (Windows x64)</strong></a>
  ·
  <a href="https://github.com/sevmorris/FL2601">macOS Version</a>
  ·
  <a href="https://sevmorris.github.io/FL2601/">Theory of Operation</a>
</p>

A Windows port of the [FL2601 Cipher Tool](https://github.com/sevmorris/FL2601)
for macOS. Same format, same crypto, full cross-platform interoperability — a
message encrypted on one platform decrypts on the other without any conversion.

Paste in a message, enter a passphrase, and get back a block of base64 you can
send over any channel — email, chat, a screenshot, a printed page. Paste that
base64 back in with the same passphrase to recover the original.

## Install

Download `FL2601.exe` from the [Releases](../../releases/latest) page and run
it. The build is self-contained — no installation or .NET runtime needed.

Requires Windows 10 or later (x64).

## Using it

**To encrypt:** enter a passphrase, confirm it in the second field, type or
paste your message, and press **ENCRYPT**. Copy the result and send it however
you like. It comes wrapped in a labelled block:

```
-----BEGIN FL2601 MESSAGE-----
Comment: FL2601-Windows

RkwyNgEBAAknwJX5kSpGJS54IxUA7LVlb3ulUNz2+hmlKMKOoc2R8MwKuvL6K596
xSZPuCR0Ri1MyqOmw/nzm1TAeyZWjlkb/6KnTZkRUpFmVoc=
-----END FL2601 MESSAGE-----
```

The wrapper is presentation only — the payload between the markers is the
message, and deleting the surrounding lines leaves something any build can
read.

**To decrypt:** switch to the **DECRYPT** tab, enter the passphrase, paste the
message, and press **DECRYPT**. Paste the whole block or just the base64 —
both work. The confirmation field disappears here: a mistyped passphrase simply
fails to decrypt, so there is nothing for a second field to catch.

Text pasted back in may carry line breaks, indentation, or stray whitespace —
from an email client that wrapped or quoted it, for example. That is handled.

**There is no passphrase recovery.** The passphrase is never stored anywhere,
by design. If you lose it, the message is gone.

## Cross-platform interoperability

Messages are byte-for-byte compatible between the macOS and Windows versions.
The binary payload follows the same
[byte layout](https://sevmorris.github.io/FL2601/#payload) documented in the
macOS project's Theory of Operation:

```
Offset  Size  Content
0       4     Magic: "FL26" (0x46 0x4C 0x32 0x36)
4       1     Version: 0x01
5       1     KDF ID: 0x01 (PBKDF2-HMAC-SHA256)
6       4     Iteration count (big-endian uint32)
10      16    Salt (random)
26      12    Nonce / IV (random)
38      var   Ciphertext (AES-256-GCM)
last 16 16    GCM authentication tag
```

The 10-byte header is passed as Additional Authenticated Data (AAD) to AES-GCM,
so any modification to the header causes decryption to fail.

You can also cross-validate using the macOS project's Node.js reference
implementation:

```bash
node tools/reference-impl.mjs encrypt "password" "hello"
# paste the output into FL2601 on Windows to decrypt

node tools/reference-impl.mjs decrypt "password" "<base64 from Windows>"
```

## How it works

Keys are derived with PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP's
current floor for SHA-256). Encryption is AES-256-GCM, which authenticates as
well as encrypts: a modified message fails to decrypt rather than decrypting to
garbage.

The payload is versioned and self-describing: the key derivation parameters
travel with each message rather than living in a constant in the source, so the
work factor can be raised in a future release without stranding messages
encrypted today.

The **[Theory of Operation](https://sevmorris.github.io/FL2601/)** from the
macOS project documents the
[byte layout](https://sevmorris.github.io/FL2601/#payload), the
[threat model](https://sevmorris.github.io/FL2601/#threat), and the reasoning
behind both. Everything there applies identically to this Windows build.

## Project structure

```
FL2601-Windows/
├── FL2601.sln
└── FL2601/
    ├── FL2601.csproj              .NET 8, WPF
    ├── App.xaml / App.xaml.cs
    ├── Services/
    │   ├── CipherEngine.cs        PBKDF2 + AES-GCM (matches Swift format)
    │   └── MessageArmor.cs        PGP-style envelope wrap/unwrap
    ├── ViewModels/
    │   └── CipherViewModel.cs     MVVM, INotifyPropertyChanged
    └── Views/
        └── MainWindow.xaml/.cs    Dark terminal UI
```

| File | Role |
| --- | --- |
| `CipherEngine.cs` | `Rfc2898DeriveBytes` for PBKDF2, `AesGcm` for AES-256-GCM. Builds and parses the binary payload in exactly the same layout as the Swift version. |
| `MessageArmor.cs` | Wraps base64 in `-----BEGIN FL2601 MESSAGE-----` markers with optional comment lines. On unwrap, strips comments (lines containing `:`), rejoins base64. Bare base64 passes through unchanged. |
| `CipherViewModel.cs` | Encrypt/decrypt mode toggle, password confirmation, async crypto on a background thread, clipboard copy, status messages. |
| `MainWindow.xaml` | Dark terminal theme (`#0A0A0A` / `#111111` background, `#33FF33` green accent, Courier New), matching the macOS version's visual style. |

## Building

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```bash
dotnet build
```

To produce a self-contained single-file release:

```bash
dotnet publish -c Release
```

The output is a single `FL2601.exe` with all dependencies (including WPF's
native libraries) embedded — no other files needed for distribution.

## License

[GPL-3.0](LICENSE) — same as the
[macOS version](https://github.com/sevmorris/FL2601). If you distribute a
modified version, you must publish your source under the same terms.
