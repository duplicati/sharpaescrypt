using System.Security.Cryptography;
using System.Buffers.Binary;

namespace SharpAESCrypt;

/// <summary>
/// Internal helper class used to encapsulate the setup process
/// </summary>
internal class SetupHelper : IDisposable
{
    /// <summary>
    /// The encryption algorithm used
    /// </summary>
    private const string ENCRYPTION_ALGORITHM = "AES";
    /// <summary>
    /// The hashing algorithm used to digest data
    /// </summary>
    private const string HASH_ALGORITHM = "SHA-256";

    /// <summary>
    /// The algorithm used to generate random data
    /// </summary>
    private const string RAND_ALGORITHM = "SHA1PRNG";

    /// <summary>
    /// The algorithm used to calculate the HMAC
    /// </summary>
    private const string HMAC_ALGORITHM = "HmacSHA256";

    /// <summary>
    /// The algorithm used for PBKDF2 in version 3
    /// </summary>
    private static readonly HashAlgorithmName PBKDF2_HASH_ALGORITHM = HashAlgorithmName.SHA512;

    /// <summary>
    /// The encryption instance
    /// </summary>
    private readonly SymmetricAlgorithm m_crypt;
    /// <summary>
    /// The hash instance
    /// </summary>
    private readonly HashAlgorithm m_hash;
    /// <summary>
    /// The random number generator instance
    /// </summary>
    private readonly RandomNumberGenerator m_rand;
    /// <summary>
    /// The HMAC algorithm
    /// </summary>
    private readonly HMAC m_hmac;

    /// <summary>
    /// Initialize the setup
    /// </summary>
    public SetupHelper()
    {
        m_crypt = (SymmetricAlgorithm)(CryptoConfig.CreateFromName(ENCRYPTION_ALGORITHM) ?? throw new SystemException($"No suitable {ENCRYPTION_ALGORITHM} implementation found"));
        m_hash = (HashAlgorithm)(CryptoConfig.CreateFromName(HASH_ALGORITHM) ?? throw new SystemException($"The required hash algorithm {HASH_ALGORITHM} is not available on this system"));
        m_rand = (RandomNumberGenerator)(System.Security.Cryptography.RandomNumberGenerator.Create(/*RAND_ALGORITHM*/) ?? throw new SystemException("The required random number generator is not available on this system"));
        m_hmac = (HMAC)(CryptoConfig.CreateFromName(HMAC_ALGORITHM) ?? throw new SystemException($"The required hash algorithm {HMAC_ALGORITHM} is not available on this system"));

        m_crypt.Padding = PaddingMode.None;
        m_crypt.Mode = CipherMode.CBC;
        m_crypt.BlockSize = Constants.BLOCK_SIZE * 8;
        m_crypt.KeySize = Constants.KEY_SIZE * 8;

        if (!m_hash.CanReuseTransform)
            throw new CryptographicException("Hash algorithm does not support reuse");
        if (!m_hash.CanTransformMultipleBlocks)
            throw new CryptographicException("The hash algortihm does not support multiple blocks");

        if (Constants.KEY_SIZE < m_hash.HashSize / 8)
            throw new CryptographicException($"Unable to digest {Constants.KEY_SIZE} bytes, as the hash algorithm only returns {m_hash.HashSize / 8} bytes");
    }

    /// <summary>
    /// Generates a bulk key and IV for encrypting data
    /// </summary>
    public BulkEncryptionKey GenerateBulkKey()
    {
        // We rely on the library to generate a secure IV and key
        m_crypt.GenerateIV();
        m_crypt.GenerateKey();

        // In case that trust was misplaced, we add some extra PRNG data
        return new BulkEncryptionKey(
            DigestRandomBytes(m_crypt.Key, Constants.KEY_GENERATION_REPETITIONS),
            DigestRandomBytes(m_crypt.IV, Constants.IV_GENERATION_REPETITIONS)
        );
    }

    /// <summary>
    /// Encodes the password according to the specified version
    /// </summary>
    /// <param name="password">The password to encode</param>
    /// <param name="fileVersion">The file version</param>
    /// <returns>The encoded password</returns>
    private static byte[] EncodePassword(string password, byte fileVersion)
    {
        // Gets the password encoding mode for the version
        var encoding = fileVersion >= 3
            ? System.Text.Encoding.UTF8
            : System.Text.Encoding.Unicode; // Unicode is UTF-16LE

        // Legacy safeguard: verify UTF-16LE preamble (was needed under Mono)
        if (fileVersion <= 2)
        {
            var preamb = encoding.GetPreamble();
            if (preamb == null || preamb.Length != 2 || preamb[0] != 0xff || preamb[1] != 0xfe)
                throw new SystemException($"The required encoding, UTF-16LE, is not supported on this system");
        }

        return encoding.GetBytes(password);
    }

    /// <summary>
    /// Creates a random IV used for encrypting the bulk key and IV.
    /// </summary>
    /// <returns>A random IV</returns>
    private ReadOnlyMemory<byte> GenerateHeaderIV()
    {
        // Build some initial entropy      
        var iv = new byte[Constants.IV_SIZE];
        BinaryPrimitives.WriteInt64BigEndian(iv.AsSpan(), DateTime.Now.Ticks);
        BinaryPrimitives.WriteUInt64BigEndian(iv.AsSpan(8), Constants.FIRST_MAC_ADDRESS);

        // The IV is generated by repeatedly hashing the IV with random data.
        // By using the MAC address and the current time, we add some initial entropy,
        // which reduces risks from a vulnerable or tampered PRNG.
        return DigestRandomBytes(iv, Constants.IV_GENERATION_REPETITIONS);
    }

    /// <summary>
    /// Generates a random header key from the password and a new IV.
    /// </summary>
    /// <param name="password">The password to use</param>
    /// <param name="version">The file version</param>
    /// <param name="iterations">The number of iterations to use for PBKDF2, or null if not using version 3+</param>
    /// <returns>The header key</returns>
    public HeaderEncryptionKey GenerateHeaderKeyAndIv(string password, byte version, int? iterations)
        => GenerateHeaderKey(password, GenerateHeaderIV(), version, iterations);

    /// <summary>
    /// Generates the header key from the password and IV.
    /// </summary>
    /// <param name="password">The password to use</param>
    /// <param name="iv">The IV to use</param>
    /// <param name="version">The file version</param>
    /// <param name="iterations">The number of iterations to use for PBKDF2, or null if not using version 3+</param>
    /// <returns>The header key</returns>
    public HeaderEncryptionKey GenerateHeaderKey(string password, ReadOnlyMemory<byte> iv, byte version, int? iterations)
        => version >= 3
            ? GenerateHeaderKeyUsingPBKDF2(password, iv, iterations ?? throw new ArgumentNullException(nameof(iterations)))
            : GenerateHeaderKeyUsingCustomKDF(password, iv, version);

    /// <summary>
    /// Generates the header key from the password and the supplied IV
    /// </summary>
    /// <param name="password">The password to use</param>
    /// <param name="iv">The IV to use</param>
    /// <param name="version">The file version</param>
    /// <returns>The header key</returns>
    private HeaderEncryptionKey GenerateHeaderKeyUsingCustomKDF(string password, ReadOnlyMemory<byte> iv, byte version)
    {
        var derivedPassword = EncodePassword(password, version);
        var key = new byte[Constants.KEY_SIZE];
        try
        {
            iv.CopyTo(key);

            for (int i = 0; i < Constants.KEY_HASH_ITERATIONS; i++)
            {
                m_hash.Initialize();
                m_hash.TransformBlock(key, 0, key.Length, key, 0);
                m_hash.TransformFinalBlock(derivedPassword, 0, derivedPassword.Length);
                var hash = m_hash.Hash ?? throw new CryptographicException("Unexpected missing hash value");
                hash.CopyTo(key.AsSpan());
                CryptographicOperations.ZeroMemory(hash);
            }

            return new HeaderEncryptionKey(key, iv);
        }
        catch
        {
            // If something fails, clear the key as it is not returned
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedPassword);
        }
    }

    /// <summary>
    /// Generates the header key from the password and IV using PBKDF2 (for version 3+).
    /// This uses HMAC-SHA512 as the PRF.
    /// </summary>
    /// <param name="password">The password to use</param>
    /// <param name="iv">The IV (salt) to use</param>
    /// <param name="iterations">The number of PBKDF2 iterations</param>
    /// <returns>The header key</returns>
    private HeaderEncryptionKey GenerateHeaderKeyUsingPBKDF2(string password, ReadOnlyMemory<byte> iv, int iterations)
    {
        if (iterations < Constants.KDF_MIN_ITERATIONS || iterations > Constants.KDF_MAX_ITERATIONS)
            throw new ArgumentOutOfRangeException(nameof(iterations), $"PBKDF2 iterations must be between {Constants.KDF_MIN_ITERATIONS} and {Constants.KDF_MAX_ITERATIONS}");

        var encodedPassword = EncodePassword(password, 3);
        var ivArray = iv.ToArray();
        try
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(encodedPassword, ivArray, iterations, PBKDF2_HASH_ALGORITHM);
            return new HeaderEncryptionKey(pbkdf2.GetBytes(Constants.KEY_SIZE), iv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encodedPassword);
            CryptographicOperations.ZeroMemory(ivArray);
        }
    }

    /// <summary>
    /// Encrypts the key and IV used to encrypt data, using the initial key and IV.
    /// </summary>
    /// <param name="headerKey">The header encryption key</param>
    /// <param name="bulkKey">The bulk encryption key</param>
    /// <param name="version">The file version</param>
    /// <returns>The encrypted AES Key (including IV) and HMAC</returns>
    public ReadOnlySpan<byte> EncryptBulkAESKeyWithHMAC(HeaderEncryptionKey headerKey, BulkEncryptionKey bulkKey, byte version)
    {
        var keyBytes = headerKey.Key.ToArray();
        var ivBytes = headerKey.IV.ToArray();
        try
        {
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, m_crypt.CreateEncryptor(keyBytes, ivBytes), CryptoStreamMode.Write);
            cs.Write(bulkKey.IV.Span);
            cs.Write(bulkKey.Key.Span);
            cs.FlushFinalBlock();

            var encryptedKey = ms.ToArray();

            m_hmac.Initialize();
            m_hmac.Key = keyBytes;
            m_hmac.TransformBlock(encryptedKey, 0, encryptedKey.Length, null, 0);

            // For version 3+, include the version byte in the HMAC calculation
            if (version >= 3)
                m_hmac.TransformFinalBlock([version], 0, 1);
            else
                m_hmac.TransformFinalBlock([], 0, 0);

            ms.Write(m_hmac.Hash ?? throw new CryptographicException("Unexpected missing hash value"));

            return ms.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(ivBytes);
        }
    }

    /// <summary>
    /// Performs repeated hashing of the data in the byte[] combined with random data.
    /// The update is performed on the input data, which is also returned.
    /// </summary>
    /// <param name="bytes">The bytes to start the digest operation with</param>
    /// <param name="repetitions">The number of repetitions to perform</param>
    /// <returns>The digested input data, which is the same array as passed in</returns>
    private ReadOnlyMemory<byte> DigestRandomBytes(byte[] bytes, int repetitions)
    {
        if (bytes.Length > (m_hash.HashSize / 8))
            throw new CryptographicException($"Unable to digest {bytes.Length} bytes, as the hash algorithm only returns {m_hash.HashSize / 8} bytes");

        m_hash.Initialize();
        m_hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
        for (var i = 0; i < repetitions; i++)
        {
            m_rand.GetBytes(bytes);
            m_hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
        }

        m_hash.TransformFinalBlock(bytes, 0, 0);
        Array.Copy(m_hash.Hash ?? throw new CryptographicException("Unexpected missing hash value"), bytes, bytes.Length);
        return bytes.AsMemory();
    }

    /// <summary>
    /// Generates the <see cref="ICryptoTransform"/> instance used to encrypt the bulk data
    /// </summary>
    /// <param name="bulkKey">The bulk key to use</param>
    /// <returns>An <see cref="ICryptoTransform"/> instance</returns>
    public ICryptoTransform CreateEncryptor(BulkEncryptionKey bulkKey)
        => m_crypt.CreateEncryptor(bulkKey.Key.ToArray(), bulkKey.IV.ToArray());

    /// <summary>
    /// Generates the <see cref="ICryptoTransform"/> instance used to decrypt the bulk data
    /// </summary>
    /// <param name="bulkKey">The bulk key to use</param>
    /// <returns>An <see cref="ICryptoTransform"/> instance</returns>
    public ICryptoTransform CreateDecryptor(BulkEncryptionKey bulkKey)
        => m_crypt.CreateDecryptor(bulkKey.Key.ToArray(), bulkKey.IV.ToArray());


    /// <summary>
    /// Creates a HMAC calculation instance for the bulk data
    /// </summary>
    /// <returns>An HMAC algortihm using the bulk encryption key</returns>
    public HMAC GetBulkHMAC(BulkEncryptionKey bulkKey)
    {
        var h = (HMAC)(CryptoConfig.CreateFromName(HMAC_ALGORITHM) ?? throw new SystemException($"The required hash algorithm {HMAC_ALGORITHM} is not available on this system"));
        h.Key = bulkKey.Key.ToArray();
        return h;
    }

    /// <summary>
    /// Decrypts the bulk key and IV and verifies the HMAC
    /// </summary>
    /// <param name="data">The encrypted IV followed by the key</param>
    /// <param name="headerKey">The header key used to decrypt the bulk key</param>
    /// <param name="version">The file version</param>
    /// <returns>The bulk encryption key</returns>
    public BulkEncryptionKey DecryptBulkEncryptionKeyAndVerifyHMAC(byte[] data, HeaderEncryptionKey headerKey, byte version)
    {
        var keyBytes = headerKey.Key.ToArray();
        var ivBytes = headerKey.IV.ToArray();
        try
        {
            m_hmac.Initialize();
            m_hmac.Key = keyBytes;
            m_hmac.TransformBlock(data, 0, Constants.IV_SIZE + Constants.KEY_SIZE, null, 0);

            // For version 3+, include the version byte in the HMAC calculation
            if (version >= 3)
                m_hmac.TransformFinalBlock([version], 0, 1);
            else
                m_hmac.TransformFinalBlock([], 0, 0);

            var calculatedhmac = m_hmac.Hash ?? throw new CryptographicException("Unexpected missing hash value");
            var hmac = data.AsSpan(Constants.IV_SIZE + Constants.KEY_SIZE);
            if (!CryptographicOperations.FixedTimeEquals(hmac, calculatedhmac))
                throw new WrongPasswordException("Invalid password or corrupted data");

            var buffer = new byte[Constants.IV_SIZE + Constants.KEY_SIZE];
            using (var ms = new MemoryStream(data))
            using (var cs = new CryptoStream(ms, m_crypt.CreateDecryptor(keyBytes, ivBytes), CryptoStreamMode.Read))
                cs.ReadExactly(buffer);

            return new BulkEncryptionKey(
                buffer.AsMemory(Constants.IV_SIZE),
                buffer.AsMemory(0, Constants.IV_SIZE));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(ivBytes);
        }
    }

    /// <summary>
    /// Disposes all members
    /// </summary>
    public void Dispose()
    {
        m_crypt?.Dispose();
        m_hash?.Dispose();
        m_rand?.Dispose();
        m_hmac?.Dispose();
    }
}
