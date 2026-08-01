using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace FL2601.Services;

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

    public static string Encrypt(string plaintext, string password, int iterations = DefaultIterations)
    {
        ValidateIterations(iterations);
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be empty.");

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);

        // Derive key via PBKDF2-HMAC-SHA256
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            KeySize);

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

    public static string Decrypt(string base64Payload, string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be empty.");

        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(base64Payload);
        }
        catch (FormatException)
        {
            throw new CryptographicException("Invalid base64 input.");
        }

        int minSize = HeaderSize + SaltSize + NonceSize + TagSize;
        if (payload.Length < minSize)
            throw new CryptographicException("Payload too short.");

        // Parse header
        if (payload[0] != Magic[0] || payload[1] != Magic[1] ||
            payload[2] != Magic[2] || payload[3] != Magic[3])
            throw new CryptographicException("Invalid magic bytes — not an FL2601 message.");

        if (payload[4] != Version)
            throw new CryptographicException($"Unsupported version: {payload[4]}.");

        if (payload[5] != KdfId)
            throw new CryptographicException($"Unsupported KDF: {payload[5]}.");

        int iterations = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(6, 4));
        ValidateIterations(iterations);

        byte[] header = payload[..HeaderSize];
        byte[] salt = payload[HeaderSize..(HeaderSize + SaltSize)];
        byte[] nonce = payload[(HeaderSize + SaltSize)..(HeaderSize + SaltSize + NonceSize)];

        int ciphertextStart = HeaderSize + SaltSize + NonceSize;
        int ciphertextLen = payload.Length - ciphertextStart - TagSize;
        byte[] ciphertext = payload[ciphertextStart..(ciphertextStart + ciphertextLen)];
        byte[] tag = payload[(payload.Length - TagSize)..];

        // Derive key
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            KeySize);

        // Decrypt
        byte[] plaintextBytes = new byte[ciphertextLen];
        using var aes = new AesGcm(key, TagSize);
        try
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes, header);
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Decryption failed — wrong password or corrupted data.");
        }

        return Encoding.UTF8.GetString(plaintextBytes);
    }

    private static void ValidateIterations(int iterations)
    {
        if (iterations < MinIterations || iterations > MaxIterations)
            throw new ArgumentOutOfRangeException(nameof(iterations),
                $"Iterations must be between {MinIterations:N0} and {MaxIterations:N0}.");
    }
}
