namespace SharpAESCrypt;

/// <summary>
/// Constants used by the AESCrypt library
/// </summary>
internal static class Constants
{
    /// <summary>
    /// The header in an AESCrypt file
    /// </summary>
    internal static readonly ReadOnlyMemory<byte> MAGIC_HEADER = "AES"u8.ToArray();

    /// <summary>
    /// The maximum supported file version
    /// </summary>
    internal const byte MAX_FILE_VERSION = 2;

    /// <summary>
    /// The size of the block unit used by the algorithm in bytes
    /// </summary>
    internal const int BLOCK_SIZE = 16;
    /// <summary>
    /// The size of the IV, in bytes, which is the same as the blocksize for AES
    /// </summary>
    internal const int IV_SIZE = 16;
    /// <summary>
    /// The size of the key. For AES-256 that is 256/8 = 32
    /// </summary>
    internal const int KEY_SIZE = 32;
    /// <summary>
    /// The size of the SHA-256 HMAC output
    /// </summary>
    internal const int HMAC_SIZE = 32;

    /// <summary>
    /// The number of iterations to use for generating the IV.
    /// Each iteration fills the buffer with cryptograph strength PRNG bytes,
    /// which are then hashed with SHA-256 to generate the final IV.
    /// </summary>
    /// <remarks>This number can be increased to increase the security of the IV</remarks>
    internal const int IV_GENERATION_REPETITIONS = 256;

    /// <summary>
    /// The number of iterations to use for generating the bulk key.
    /// Each iteration fills the buffer with cryptograph strength PRNG bytes,
    /// which are then hashed with SHA-256 to generate the final IV.
    /// </summary>
    /// <remarks>This number can be increased to increase the security of the key</remarks>
    internal const int KEY_GENERATION_REPETITIONS = 32;

    /// <summary>
    /// The number of iterations to use for hashing the key
    /// </summary>
    /// <remarks>This number is required to be 8192 by the AESCrypt specification</remarks>
    internal const int KEY_HASH_ITERATIONS = 8192;
}
