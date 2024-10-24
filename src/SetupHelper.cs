using System.Text;
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
    /// The encoding scheme for the password.
    /// A check is made when using the encoding, that it is indeed UTF-16LE.
    /// </summary>
    private const string PASSWORD_ENCODING = "utf-16le";

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
    /// <param name="mode">The mode to prepare for</param>
    /// <param name="password">The password used to encrypt or decrypt</param>
    /// <param name="iv">The IV used, set to null if encrypting</param>
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
    /// Generates the header key from the password and creates a random IV for the bulk key
    /// </summary>
    /// <param name="password">The password to use</param>
    /// <returns>The header key</returns>
    public HeaderEncryptionKey GenerateHeaderKeyAndIv(string password)
    {
        var iv = GenerateHeaderIV();
        return new HeaderEncryptionKey(GenerateHeaderKeyFromPasswordAndIV(EncodePassword(password), iv), iv);
    }

    /// <summary>
    /// Generates the header key from the password and the supplied IV
    /// </summary>
    /// <param name="password">The password to use</param>
    /// <param name="iv">The IV to use</param>
    /// <returns>The header key</returns>
    public HeaderEncryptionKey GenerateHeaderKeyWithIv(string password, Memory<byte> iv)
        => new HeaderEncryptionKey(GenerateHeaderKeyFromPasswordAndIV(EncodePassword(password), iv), iv);

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
    /// Encodes the password in UTF-16LE and verifies that the encoding is correct.
    /// </summary>
    /// <param name="password">The password to encode as a byte array</param>
    /// <returns>The password encoded as a byte array</returns>
    private static byte[] EncodePassword(string password)
    {
        var e = Encoding.GetEncoding(PASSWORD_ENCODING);

        var preamb = e?.GetPreamble();
        if (e == null || preamb == null || preamb.Length != 2)
            throw new SystemException($"The required encoding, {PASSWORD_ENCODING}, is not supported on this system");

        if (preamb[0] == 0xff && preamb[1] == 0xfe)
            return e.GetBytes(password);
        else
            throw new SystemException($"The required encoding, {PASSWORD_ENCODING}, is not supported on this system (looks like UTF-16BE)");
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
    /// Generates a key based on the IV and the password.
    /// This key is used to encrypt the bulk key and IV.
    /// </summary>
    /// <param name="password">The password supplied</param>
    /// <returns>The bulk key generated</returns>
    private ReadOnlyMemory<byte> GenerateHeaderKeyFromPasswordAndIV(byte[] password, ReadOnlyMemory<byte> iv1)
    {
        var key = new byte[Constants.KEY_SIZE];
        iv1.CopyTo(key);

        for (int i = 0; i < Constants.KEY_HASH_ITERATIONS; i++)
        {
            m_hash.Initialize();
            m_hash.TransformBlock(key, 0, key.Length, key, 0);
            m_hash.TransformFinalBlock(password, 0, password.Length);
            key = m_hash.Hash ?? throw new CryptographicException("Unexpected missing hash value");
        }

        return key;
    }

    /// <summary>
    /// Encrypts the key and IV used to encrypt data, using the initial key and IV.
    /// </summary>
    /// <returns>The encrypted AES Key (including IV) and HMAC</returns>
    public ReadOnlySpan<byte> EncryptBulkAESKeyWithHMAC(HeaderEncryptionKey headerKey, BulkEncryptionKey bulkKey)
    {
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, m_crypt.CreateEncryptor(headerKey.Key.ToArray(), headerKey.IV.ToArray()), CryptoStreamMode.Write);
        cs.Write(bulkKey.IV.Span);
        cs.Write(bulkKey.Key.Span);
        cs.FlushFinalBlock();

        var encryptedKey = ms.ToArray();

        m_hmac.Initialize();
        m_hmac.Key = headerKey.Key.ToArray();
        m_hmac.TransformFinalBlock(encryptedKey, 0, encryptedKey.Length);

        ms.Write(m_hmac.Hash ?? throw new CryptographicException("Unexpected missing hash value"));

        return ms.ToArray();
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
    /// <returns>The bulk encryption key</returns>
    public BulkEncryptionKey DecryptBulkEncryptionKeyAndVerifyHMAC(byte[] data, HeaderEncryptionKey headerKey)
    {
        m_hmac.Initialize();
        m_hmac.Key = headerKey.Key.ToArray();
        m_hmac.TransformFinalBlock(data, 0, Constants.IV_SIZE + Constants.KEY_SIZE);
        var calculatedhmac = m_hmac.Hash ?? throw new CryptographicException("Unexpected missing hash value");
        var hmac = data.AsSpan(Constants.IV_SIZE + Constants.KEY_SIZE);
        if (!hmac.SequenceEqual(calculatedhmac))
            throw new WrongPasswordException("Invalid password or corrupted data");

        var buffer = new byte[Constants.IV_SIZE + Constants.KEY_SIZE];
        using (var ms = new MemoryStream(data))
        using (var cs = new CryptoStream(ms, m_crypt.CreateDecryptor(headerKey.Key.ToArray(), headerKey.IV.ToArray()), CryptoStreamMode.Read))
            cs.ReadExactly(buffer);

        return new BulkEncryptionKey(
            buffer.AsMemory(Constants.IV_SIZE),
            buffer.AsMemory(0, Constants.IV_SIZE));
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
