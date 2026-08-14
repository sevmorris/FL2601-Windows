using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace FL2601.Services;

/// <summary>
/// What a payload declares about itself, readable without the passphrase.
///
/// Everything here comes from the header and the block's length, so obtaining
/// it costs nothing and reveals nothing the ciphertext was hiding: an observer
/// could compute the same figures from the base64 alone.
/// </summary>
public sealed record PayloadInfo(
    int TotalBytes,
    byte Version,
    byte Kdf,
    int Iterations,
    int SaltBytes,
    int NonceBytes,
    int CiphertextBytes,
    int TagBytes)
{
    /// <summary>
    /// AES-GCM is a stream cipher construction, so ciphertext and plaintext are
    /// the same length. This is exact, not an estimate.
    /// </summary>
    public int PlaintextBytes => CiphertextBytes;
}

public static class CipherEngine
{
    private static readonly byte[] Magic = "FL26"u8.ToArray();
    private const byte Version = 0x01;
    private const byte KdfId = 0x01; // PBKDF2-HMAC-SHA256

    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32; // AES-256
    private const int HeaderSize = 10; // 4 magic + 1 version + 1 kdf + 4 iterations

    public const int DefaultIterations = 600_000;
    public const int MinIterations = 10_000;
    public const int MaxIterations = 10_000_000;

    public static string Encrypt(string plaintext, string passphrase, int iterations = DefaultIterations)
    {
        ValidateIterations(iterations);
        if (string.IsNullOrEmpty(passphrase))
            throw new ArgumentException("Passphrase cannot be empty.");

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] key = DeriveKey(passphrase, salt, iterations);

        try
        {
            // Build header (AAD)
            byte[] header = new byte[HeaderSize];
            Magic.CopyTo(header, 0);
            header[4] = Version;
            header[5] = KdfId;
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(6, 4), (uint)iterations);

            // Encrypt with AES-256-GCM
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[TagSize];

            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag, header);

            // Assemble: header | salt | nonce | ciphertext | tag
            byte[] payload = new byte[HeaderSize + SaltSize + NonceSize + ciphertext.Length + TagSize];
            int offset = 0;
            header.CopyTo(payload, offset); offset += HeaderSize;
            salt.CopyTo(payload, offset); offset += SaltSize;
            nonce.CopyTo(payload, offset); offset += NonceSize;
            ciphertext.CopyTo(payload, offset); offset += ciphertext.Length;
            tag.CopyTo(payload, offset);

            return Convert.ToBase64String(payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }

    /// <summary>
    /// Reads a payload's header without deriving a key or decrypting anything.
    /// </summary>
    public static PayloadInfo Inspect(string input) => Parse(input).Info;

    public static string Decrypt(string input, string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
            throw new ArgumentException("Passphrase cannot be empty.");

        ParsedPayload parsed = Parse(input);

        byte[] key = DeriveKey(passphrase, parsed.Salt, parsed.Info.Iterations);
        byte[] plaintextBytes = new byte[parsed.Ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            try
            {
                aes.Decrypt(parsed.Nonce, parsed.Ciphertext, parsed.Tag, plaintextBytes, parsed.Header);
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(plaintextBytes);
                throw new CryptographicException("Decryption failed — wrong passphrase or corrupted data.");
            }

            return Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }

    private readonly record struct ParsedPayload(
        PayloadInfo Info,
        byte[] Header,
        byte[] Salt,
        byte[] Nonce,
        byte[] Ciphertext,
        byte[] Tag);

    /// <summary>
    /// Header parsing, shared by <see cref="Decrypt"/> and <see cref="Inspect"/>
    /// so the two can never disagree about where a field begins.
    /// </summary>
    private static ParsedPayload Parse(string input)
    {
        // Accept either an armored block or bare base64. The envelope is only a
        // hint about where the payload starts; nothing in it is trusted, and
        // input without one is passed through untouched.
        string cleaned = StripWhitespace(MessageArmor.Unwrap(input));

        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(cleaned);
        }
        catch (FormatException)
        {
            throw new CryptographicException("Invalid base64 input.");
        }

        int minSize = HeaderSize + SaltSize + NonceSize + TagSize;
        if (payload.Length < minSize)
            throw new CryptographicException("Payload too short.");

        if (payload[0] != Magic[0] || payload[1] != Magic[1] ||
            payload[2] != Magic[2] || payload[3] != Magic[3])
            throw new CryptographicException("Invalid magic bytes — not an FL2601 message.");

        if (payload[4] != Version)
            throw new CryptographicException($"Unsupported version: {payload[4]}.");

        if (payload[5] != KdfId)
            throw new CryptographicException($"Unsupported KDF: {payload[5]}.");

        // Key derivation happens before authentication can possibly succeed, so
        // a hostile payload could otherwise ask the app to spin on four billion
        // rounds. The tag check would eventually reject it, but only after the
        // damage to responsiveness was done.
        uint declared = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(6, 4));
        if (declared < MinIterations || declared > MaxIterations)
            throw new CryptographicException(
                $"Message declares {declared:N0} iterations, outside the accepted range.");

        int iterations = (int)declared;
        int ciphertextStart = HeaderSize + SaltSize + NonceSize;
        int ciphertextLen = payload.Length - ciphertextStart - TagSize;

        var info = new PayloadInfo(
            TotalBytes: payload.Length,
            Version: payload[4],
            Kdf: payload[5],
            Iterations: iterations,
            SaltBytes: SaltSize,
            NonceBytes: NonceSize,
            CiphertextBytes: ciphertextLen,
            TagBytes: TagSize);

        return new ParsedPayload(
            info,
            Header: payload[..HeaderSize],
            Salt: payload[HeaderSize..(HeaderSize + SaltSize)],
            Nonce: payload[(HeaderSize + SaltSize)..ciphertextStart],
            Ciphertext: payload[ciphertextStart..(ciphertextStart + ciphertextLen)],
            Tag: payload[(payload.Length - TagSize)..]);
    }

    private static string StripWhitespace(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (!char.IsWhiteSpace(c))
                sb.Append(c);
        }
        return sb.ToString();
    }

    private static byte[] DeriveKey(string passphrase, byte[] salt, int iterations)
    {
        byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(passphraseBytes, salt, iterations, HashAlgorithmName.SHA256, KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    private static void ValidateIterations(int iterations)
    {
        if (iterations < MinIterations || iterations > MaxIterations)
            throw new ArgumentOutOfRangeException(nameof(iterations),
                $"Iterations must be between {MinIterations:N0} and {MaxIterations:N0}.");
    }
}
