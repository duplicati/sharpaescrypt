namespace SharpAESCrypt;

/// <summary>
/// Sets the file extensions to apply when creating a new encrypted file
/// </summary>
/// <param name="InsertCreatedByIdentifier">Insert the creator identifier</param>
/// <param name="InsertTimeStamp">Insert a timestamp</param>
/// <param name="InsertPlaceholder">Insert a placeholder for other tools to append headers</param>
/// <param name="FileVersion">The file version to use</param>
/// <param name="AdditionalExtensions">Additional extensions to add to the file</param>
/// <param name="LeaveOpen">Leave the file open after encryption</param>
public record EncryptionOptions(
    bool InsertCreatedByIdentifier = true,
    bool InsertTimeStamp = true,
    bool InsertPlaceholder = true,
    byte FileVersion = AESCrypt.DEFAULT_FILE_VERSION,
    IEnumerable<KeyValuePair<string, byte[]>>? AdditionalExtensions = null,
    bool LeaveOpen = false
)
{
    /// <summary>
    /// The default encryption options to use
    /// </summary>
    public static readonly EncryptionOptions Default = new();
}

