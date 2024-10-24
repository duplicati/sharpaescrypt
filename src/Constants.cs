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

    /// <summary>
    /// Helper function for setting the `FIRST_MAC_ADDRESS` varible. It retrieves the first MAC address of the system. If no MAC address is found, or one of the system functions throws an exception, a default MAC address is used.
    /// </summary>
    /// <remarks>The default MAC address used is 01:23:45:67:89:ab</remarks>
    /// <returns>The MAC address of the first network interface that has a MAC address, or the default MAC address if no such interface is found.</returns>
    private static byte[] GetFirstMacAddress()
    {
        byte[] default_mac = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab];
        try {
            return System.Net.NetworkInformation.NetworkInterface
                    .GetAllNetworkInterfaces()
                    .Select(ni => { try { return ni.GetPhysicalAddress().GetAddressBytes(); } catch { return []; } })
                    .Where(mac => mac.Length > 0 && !mac.All(b => b == 0))
                    .FirstOrDefault(default_mac);
        } catch {
            return default_mac;
        }
    }

    /// <summary>
    /// The MAC address of the first network interface that has a MAC address.
    /// </summary>
    /// <remarks>If no such interface is found, a default MAC address is used (01:23:45:67:89:ab)</remarks>
    internal static readonly ulong FIRST_MAC_ADDRESS = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(
    [
        .. GetFirstMacAddress(),
        .. new byte[2],
    ]);
}
