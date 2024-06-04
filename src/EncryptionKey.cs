namespace SharpAESCrypt;

/// <summary>
/// Represents a header encryption key
/// </summary>
/// <param name="Key">The encryption key</param>
/// <param name="IV">The initialization vector</param>
public record HeaderEncryptionKey(ReadOnlyMemory<byte> Key, ReadOnlyMemory<byte> IV);

/// <summary>
/// Represents a bulk encryption key
/// </summary>
/// <param name="Key">The encryption key</param>
/// <param name="IV">The initialization vector</param>
public record BulkEncryptionKey(ReadOnlyMemory<byte> Key, ReadOnlyMemory<byte> IV);
