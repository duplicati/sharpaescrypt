namespace SharpAESCrypt;

/// <summary>
/// Provides an API for AESCrypt encryption and decryption.
/// </summary>
/// <remarks>
/// The file format declare support for 2^64 bytes encrypted data, but .Net has trouble 
/// with files more than 2^63 bytes long, so this module 'only' supports 2^63 bytes 
/// (long vs ulong).
///  </remarks>
public static class AESCrypt
{
    /// <summary>
    /// The default file format options to use
    /// </summary>
    public const byte DEFAULT_FILE_VERSION = 2;

    /// <summary>
    /// Extracts the unencrypted, unverified extensions from the header.
    /// Note that this advances the stream position, and it should be
    /// reset to the beginning before decryption.
    /// Since the header extensions are not encrypted, they can be obtained
    /// without providing a password.
    /// </summary>
    /// <param name="stream">The stream to read from</param>
    /// <returns>The extensions found in the header, if any</returns>
    public static IEnumerable<KeyValuePair<string, byte[]>> ReadExtensions(Stream stream)
        => DecryptingStreamInternal.ExtractExtensionsFromHeader(stream);

    /// <summary>
    /// Extracts the unencrypted, unverified extensions from the header.
    /// Since the header extensions are not encrypted, they can be obtained
    /// without providing a password.
    /// </summary>
    /// <param name="filename">The file to read from</param>
    /// <returns>The extensions found in the header, if any</returns>
    public static IEnumerable<KeyValuePair<string, byte[]>> ReadExtensions(string filename)
    {
        using (var fs = File.OpenRead(filename))
            return ReadExtensions(fs);
    }


    /// <summary>
    /// Encrypts a stream using the supplied password
    /// </summary>
    /// <param name="password">The password to decrypt with</param>
    /// <param name="input">The stream with unencrypted data</param>
    /// <param name="output">The encrypted output stream</param>
    /// <param name="options">The encryption options to use</param>
    public static void Encrypt(string password, Stream input, Stream output, EncryptionOptions? options = default)
    {
        using var c = new EncryptingStream(password, output, options);
        input.CopyTo(c);
        c.FlushFinalBlock();
    }

    /// <summary>
    /// Encrypts a stream using the supplied password
    /// </summary>
    /// <param name="password">The password to decrypt with</param>
    /// <param name="input">The stream with unencrypted data</param>
    /// <param name="output">The encrypted output stream</param>
    /// <param name="options">The encryption options to use</param>
    public static async Task EncryptAsync(string password, Stream input, Stream output, EncryptionOptions? options = default, CancellationToken ct = default)
    {
        using var c = new EncryptingStream(password, output, options);
        await input.CopyToAsync(c, ct);
        c.FlushFinalBlock();
    }

    /// <summary>
    /// Decrypts a stream using the supplied password
    /// </summary>
    /// <param name="password">The password to encrypt with</param>
    /// <param name="input">The stream with encrypted data</param>
    /// <param name="output">The unencrypted output stream</param>
    /// <param name="options">The decryption options to use</param>
    public static void Decrypt(string password, Stream input, Stream output, DecryptionOptions? options = default)
    {
        using var c = new DecryptingStream(password, input, options);
        c.CopyTo(output);
    }

    /// <summary>
    /// Decrypts a stream using the supplied password
    /// </summary>
    /// <param name="password">The password to encrypt with</param>
    /// <param name="input">The stream with encrypted data</param>
    /// <param name="output">The unencrypted output stream</param>
    /// <param name="options">The decryption options to use</param>
    public static async Task DecryptAsync(string password, Stream input, Stream output, DecryptionOptions? options = default, CancellationToken ct = default)
    {
        using var c = new DecryptingStream(password, input, options);
        await c.CopyToAsync(output, ct);
    }

    /// <summary>
    /// Encrypts a file using the supplied password
    /// </summary>
    /// <param name="password">The password to encrypt with</param>
    /// <param name="inputfile">The file with unencrypted data</param>
    /// <param name="outputfile">The encrypted output file</param>
    /// <param name="maxThreads">Maximum threads allowed for SharpAESCrypt. </param>
    /// <param name="options">The encryption options to use</param>
    public static void Encrypt(string password, string inputfile, string outputfile, EncryptionOptions? options = default)
    {
        using (var infs = File.OpenRead(inputfile))
        using (var outfs = File.Create(outputfile))
            Encrypt(password, infs, outfs, options);
    }

    /// <summary>
    /// Encrypts a file using the supplied password
    /// </summary>
    /// <param name="password">The password to encrypt with</param>
    /// <param name="inputfile">The file with unencrypted data</param>
    /// <param name="outputfile">The encrypted output file</param>
    /// <param name="maxThreads">Maximum threads allowed for SharpAESCrypt. </param>
    /// <param name="options">The encryption options to use</param>
    /// <param name="ct">The cancellation token to use</param>
    public static async Task EncryptAsync(string password, string inputfile, string outputfile, EncryptionOptions? options = default, CancellationToken ct = default)
    {
        using (var infs = File.OpenRead(inputfile))
        using (var outfs = File.Create(outputfile))
            await EncryptAsync(password, infs, outfs, options, ct);
    }

    /// <summary>
    /// Decrypts a file using the supplied password
    /// </summary>
    /// <param name="password">The password to decrypt with</param>
    /// <param name="inputfile">The file with encrypted data</param>
    /// <param name="outputfile">The unencrypted output file</param>
    /// <param name="options">The decryption options to use</param>
    public static void Decrypt(string password, string inputfile, string outputfile, DecryptionOptions? options = default)
    {
        using (var infs = File.OpenRead(inputfile))
        using (var outfs = File.Create(outputfile))
            Decrypt(password, infs, outfs, options);
    }

    /// <summary>
    /// Decrypts a file using the supplied password
    /// </summary>
    /// <param name="password">The password to decrypt with</param>
    /// <param name="inputfile">The file with encrypted data</param>
    /// <param name="outputfile">The unencrypted output file</param>
    /// <param name="options">The decryption options to use</param>
    /// <param name="ct">The cancellation token to use</param>
    public static async Task DecryptAsync(string password, string inputfile, string outputfile, DecryptionOptions? options = default, CancellationToken ct = default)
    {
        using (var infs = File.OpenRead(inputfile))
        using (var outfs = File.Create(outputfile))
            await DecryptAsync(password, infs, outfs, options, ct);
    }
}