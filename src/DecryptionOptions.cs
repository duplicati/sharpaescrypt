namespace SharpAESCrypt;

/// <summary>
/// Options for decrypting a file
/// </summary>
/// <param name="MinVersion">The minimum file version to accept</param>
/// <param name="LeaveOpen">Leave the file open after decryption</param>
/// <param name="IgnorePaddingBytes">Ignore padding byte values; this is for compatibility with the mainline client which uses random data for padding.</param>
/// <param name="IgnoreFileLength">Ignore the file length; this is for recovery mode attempting to return the last block even if damaged.</param>
public record DecryptionOptions(
    int MinVersion = AESCrypt.DEFAULT_FILE_VERSION,
    bool LeaveOpen = false,
    bool IgnorePaddingBytes = false,
    bool IgnoreFileLength = false
)
{
    /// <summary>
    /// The default decryption options to use
    /// </summary>
    public static readonly DecryptionOptions Default = new();
}

