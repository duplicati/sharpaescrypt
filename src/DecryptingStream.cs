using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SharpAESCrypt;

/// <summary>
/// Stream interface for decrypting
/// </summary>
public class DecryptingStream : Stream
{
    /// <summary>
    /// The internal stream used for decryption
    /// </summary>
    private readonly DecryptingStreamInternal m_internalStream;

    /// <summary>
    /// Constructs a new DecryptingStream instance, operating on the supplied stream
    /// </summary>
    /// <param name="password">The password used for decryption</param>
    /// <param name="stream">The stream to operate on, must be readable</param>
    /// <param name="options">The options to use</param>
    public DecryptingStream(string password, Stream stream, DecryptionOptions? options = null)
        => m_internalStream = new DecryptingStreamInternal(password, stream, options);

    /// <summary>
    /// The file version
    /// </summary>
    public byte Version => m_internalStream.Version;

    /// <summary>
    /// The extensions read from the header
    /// </summary>
    public IEnumerable<KeyValuePair<string, byte[]>> Extensions => m_internalStream.Extensions;

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => false;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => m_internalStream.Length;
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count) => m_internalStream.Read(buffer, offset, count);

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void Flush() { }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
            m_internalStream.Dispose(disposing);
        base.Dispose(disposing);
    }
}

/// <summary>
/// The internal implementation of a decrypting stream.
/// This class prevents direct access and makes it simpler
/// to manage the public API
/// </summary>
internal partial class DecryptingStreamInternal
{
    /// <summary>
    /// The stream to read encrypted data from
    /// </summary>
    private readonly Stream m_stream;
    /// <summary>
    /// True if the stream should be left open after decryption, false otherwise
    /// </summary>
    private readonly bool m_leaveOpen;
    /// <summary>
    /// The crypto transform instance
    /// </summary>
    private readonly ICryptoTransform m_cryptoTransform;
    /// <summary>
    /// The HMAC instance
    /// </summary>
    private readonly HashAlgorithm m_hmac;
    /// <summary>
    /// The number of bytes reserved at the end of the stream for the last block + HMAC
    /// </summary>
    private readonly int m_reservedBytes;
    /// <summary>
    /// Flag to toggle compatibility mode with some clients, which write random data for padding.
    /// The C# and Java implementations write padding similar to PCKS7, but does not write the empty padding block.
    /// The mainline client and others are vulnerable to injecting up to 15 bytes of random data into the end of the stream,
    /// but this library defaults to strict padding checks by default.
    /// </summary>
    private readonly bool m_ignorePaddingBytes;
    /// <summary>
    /// Flag to ignore the file length, used for recovery of damaged files
    /// </summary>
    private readonly bool m_ignoreFileLength;
    /// <summary>
    /// The length of the data read
    /// </summary>
    private long m_length;

    /// <summary>
    /// The last block length, only filled for v0
    /// </summary>
    private readonly byte m_lastBlockLen;

    /// <summary>
    /// True if the trailing HMAC has been read and verified, false otherwise.
    /// </summary>
    private bool m_hasReadFooter = false;

    /// <summary>
    /// The list of extensions read from the stream
    /// </summary>
    public IEnumerable<KeyValuePair<string, byte[]>> Extensions { get; init; }

    /// <summary>
    /// The file version
    /// </summary>
    public byte Version { get; init; }

    /// <summary>
    /// The length of the data read so far
    /// </summary>
    public long Length => m_length;
    /// <summary>
    /// The number of blocks to allocate in the buffer
    /// </summary>
    private const int BLOCKS_IN_BUFFER = 1024;

    /// <summary>
    /// A buffer for maximizing read-ahead performance
    /// </summary>
    private readonly ByteBuffer m_blockBuffer = new ByteBuffer(Constants.BLOCK_SIZE * BLOCKS_IN_BUFFER);

    /// <summary>
    /// Storage for bytes read across block boundaries, also used for read-ahead
    /// </summary>
    private readonly ByteBuffer m_extraDecryptedBytes = new ByteBuffer(Constants.BLOCK_SIZE * BLOCKS_IN_BUFFER);

    /// <summary>
    /// Constructs a new AESCrypt instance, operating on the supplied stream
    /// </summary>
    /// <param name="password">The password used for encryption or decryption</param>
    /// <param name="stream">The stream to operate on, must be writeable for encryption, and readable for decryption</param>
    /// <param name="options">The options to use</param>
    public DecryptingStreamInternal(string password, Stream stream, DecryptionOptions? options = null)
    {
        //Basic input checks
        if (stream == null)
            throw new ArgumentNullException("stream");
        if (password == null)
            throw new ArgumentNullException("password");
        if (!stream.CanRead)
            throw new ArgumentException("The stream must be readable", "stream");

        options ??= DecryptionOptions.Default;
        using var helper = new SetupHelper();

        //Read and validate
        (var headerKey, var bulkKey, var version, var extensions, m_lastBlockLen) = ReadEncryptionHeader(stream, helper, password, options);

        // Set up properties based on the header
        Version = version;
        Extensions = extensions;
        if (Version < options.MinVersion)
            throw new InvalidDataException($"File version was {Version} but minimum allowed version is {options.MinVersion}");

        // Preserve the last block for special handling of padding, and the HMAC
        m_reservedBytes = Constants.BLOCK_SIZE + Constants.HMAC_SIZE + (version >= 1 ? 1 : 0);
        m_ignorePaddingBytes = options.IgnorePaddingBytes;
        m_ignoreFileLength = options.IgnoreFileLength;

        // All ready, set up the instances
        m_stream = stream;
        m_leaveOpen = options.LeaveOpen;
        m_hmac = helper.GetBulkHMAC(bulkKey);
        m_cryptoTransform = helper.CreateDecryptor(bulkKey);
    }

    /// <summary>
    /// The values extracted from the header
    /// </summary>
    /// <param name="HeaderKey">The header key</param>
    /// <param name="BulkKey">The bulk key</param>
    /// <param name="Version">The file version</param>
    /// <param name="Extensions">The list of extensions</param>
    /// <param name="LastBlockLen">The last block length</param>
    private record HeaderData(
        HeaderEncryptionKey HeaderKey,
        BulkEncryptionKey BulkKey,
        byte Version,
        List<KeyValuePair<string, byte[]>> Extensions,
        byte LastBlockLen
    );

    /// <summary>
    /// Helper function to read and validate the header
    /// </summary>
    /// <param name="stream">The stream to read from</param>
    /// <param name="helper">The setup helper instance</param>
    /// <param name="password">The password to use</param>
    /// <param name="options">The decryption options to use</param>
    private static HeaderData ReadEncryptionHeader(Stream stream, SetupHelper helper, string password, DecryptionOptions options)
    {
        var tmp = new byte[Constants.MAGIC_HEADER.Length + 2];
        try { stream.ReadExactly(tmp); }
        catch { throw new InvalidDataException($"Failed to read {tmp.Length} bytes, likely not an encrypted archive"); }

        if (!Constants.MAGIC_HEADER.Span.SequenceEqual(tmp.AsSpan(0, Constants.MAGIC_HEADER.Length)))
            throw new InvalidDataException($"Invalid header value: {BitConverter.ToString(tmp)}");

        var version = tmp[Constants.MAGIC_HEADER.Length];
        if (version > Constants.MAX_FILE_VERSION)
            throw new InvalidDataException($"File version was {version} but max supported version is {Constants.MAX_FILE_VERSION}");

        var lastBlockLenByte = tmp[Constants.MAGIC_HEADER.Length + 1];
        if (version == 0)
        {
            if (lastBlockLenByte >= Constants.BLOCK_SIZE)
                throw new InvalidDataException($"Archive v0 last-block size is {lastBlockLenByte} which is larger than the block size: {Constants.BLOCK_SIZE}");

        }
        else if (lastBlockLenByte != 0)
            throw new InvalidDataException($"Invalid reserved value in header: {lastBlockLenByte}");

        var extensions = new List<KeyValuePair<string, byte[]>>();

        //Extensions are only supported in v2+
        if (version >= 2)
        {
            var buffer = new byte[ushort.MaxValue];
            while (true)
            {
                stream.ReadExactly(buffer.AsSpan(0, 2));
                var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(buffer);

                // No more extensions
                if (extensionLength == 0)
                    break;

                var dataspan = buffer.AsSpan(0, extensionLength);
                stream.ReadExactly(dataspan);
                var separatorIndex = dataspan.IndexOf((byte)0);
                if (separatorIndex < 0)
                    throw new InvalidDataException("Invalid extension data, missing separator");

                var key = System.Text.Encoding.UTF8.GetString(dataspan.Slice(0, separatorIndex));
                var value = dataspan.Slice(separatorIndex + 1).ToArray();
                extensions.Add(new KeyValuePair<string, byte[]>(key, value));
            }
        }

        var headerIv = new byte[Constants.IV_SIZE];
        stream.ReadExactly(headerIv);

        var headerKey = helper.GenerateHeaderKeyWithIv(password, headerIv);

        BulkEncryptionKey bulkKey;
        if (version >= 1)
        {
            var bulkKeyAndHmac = new byte[Constants.IV_SIZE + Constants.KEY_SIZE + Constants.HMAC_SIZE];
            stream.ReadExactly(bulkKeyAndHmac);

            bulkKey = helper.DecryptBulkEncryptionKeyAndVerifyHMAC(bulkKeyAndHmac, headerKey);
        }
        else
        {
            bulkKey = new BulkEncryptionKey(headerKey.Key, headerKey.IV);
        }

        return new HeaderData(headerKey, bulkKey, version, extensions, lastBlockLenByte);
    }

    /// <summary>
    /// Reads unencrypted data from the underlying stream
    /// </summary>
    /// <param name="buffer">The buffer to read data into</param>
    /// <param name="offset">The offset into the buffer</param>
    /// <param name="count">The number of bytes to read</param>
    /// <returns>The number of bytes read</returns>
    public int Read(byte[] buffer, int offset, int count)
    {
        var read = 0;

        // Process data from the stream in chuncks
        while (count > 0)
        {
            // If we have read ahead data, return that first
            if (m_extraDecryptedBytes.Length > 0)
            {
                var preparedBytes = Math.Min(m_extraDecryptedBytes.Length, count);
                m_extraDecryptedBytes.Consume(preparedBytes).CopyTo(buffer.AsSpan(offset));

                // Update counters
                count -= preparedBytes;
                offset += preparedBytes;
                read += preparedBytes;
                m_length += preparedBytes;
            }

            // If we have read all data, return
            if (m_hasReadFooter || count == 0)
                return read;

            // Read as many encrypted bytes as possible
            var r = m_stream.Read(m_blockBuffer.Array, m_blockBuffer.Offset + m_blockBuffer.Length, m_blockBuffer.RemainingCapacity);
            if (r == 0)
                break;

            // Update the length of the data read
            m_blockBuffer.Appended(r);

            // Process as many blocks as possible, keeping the trailing bytes in the buffer, still encrypted        
            var bytesToDecrypt = Math.Max(0, Math.Min(m_extraDecryptedBytes.Capacity, m_blockBuffer.Length - m_reservedBytes) / Constants.BLOCK_SIZE * Constants.BLOCK_SIZE);

            // Full blocks can be decrypted directly to the output buffer for performance
            var callerBytesDirect = Math.Min(bytesToDecrypt, count / Constants.BLOCK_SIZE * Constants.BLOCK_SIZE);
            if (callerBytesDirect > 0)
            {
                m_hmac.TransformBlock(m_blockBuffer.Array, m_blockBuffer.Offset, callerBytesDirect, null, 0);
                m_cryptoTransform.TransformBlock(m_blockBuffer.Array, m_blockBuffer.Offset, callerBytesDirect, buffer, offset);
                count -= callerBytesDirect;
                offset += callerBytesDirect;
                read += callerBytesDirect;
                m_length += callerBytesDirect;
                bytesToDecrypt -= callerBytesDirect;
                m_blockBuffer.Consume(callerBytesDirect);
            }

            // Decrypt any read-ahead data in full blocks
            if (bytesToDecrypt > 0)
            {
                m_hmac.TransformBlock(m_blockBuffer.Array, m_blockBuffer.Offset, bytesToDecrypt, null, 0);
                m_cryptoTransform.TransformBlock(m_blockBuffer.Array, m_blockBuffer.Offset, bytesToDecrypt, m_blockBuffer.Array, m_blockBuffer.Offset);

                // Copy decrypted requested data to output buffer and store the rest in the decrypted buffer
                var decrypted = m_blockBuffer.Consume(bytesToDecrypt);
                var toCopy = Math.Min(decrypted.Length, count);
                decrypted.Slice(0, toCopy).CopyTo(buffer.AsSpan(offset));
                m_extraDecryptedBytes.Append(decrypted.Slice(toCopy));

                // Update counters
                count -= toCopy;
                offset += toCopy;
                read += toCopy;
                m_length += toCopy;
            }

            // Prepare for the next iteration
            m_blockBuffer.Optimize();
        }

        if (!m_hasReadFooter && (count > 0 || read == 0))
        {
            m_hasReadFooter = true;

            // Special case for zero-byte cleartext, no padding, not conforming to PCKS7
            if (m_blockBuffer.Length < m_reservedBytes)
            {
                m_cryptoTransform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                m_hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                if (Version == 0 && m_lastBlockLen != 0)
                    throw new HashMismatchException("Content has been tampered with, do not trust content: invalid v0 padding length");
                else if (Version != 0 && m_blockBuffer.Consume(1)[0] != 0)
                    throw new HashMismatchException("Content has been tampered with, do not trust content: invalid padding length");
            }
            else
            {
                // Last block in buffer, decrypt and verify padding
                m_hmac.TransformFinalBlock(m_blockBuffer.Array, m_blockBuffer.Offset, Constants.BLOCK_SIZE);
                m_cryptoTransform.TransformBlock(m_blockBuffer.Array, m_blockBuffer.Offset, Constants.BLOCK_SIZE, m_blockBuffer.Array, m_blockBuffer.Offset);
                m_cryptoTransform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                // NOTE: In any version, the last block length is not covered by the HMAC.
                // This means an attacker can modify the last block length, but not the content.
                // The check here is incompatible with the mainline client, but is harder to manipulate.
                // An attacker can still expand the file by up to 15 bytes, but not shorten it.                
                var decrypted = m_blockBuffer.Consume(Constants.BLOCK_SIZE);
                var trailBytes = Version == 0
                    ? m_lastBlockLen
                    : m_blockBuffer.Consume(1)[0];

                if (!m_ignoreFileLength && trailBytes >= Constants.BLOCK_SIZE)
                    throw new HashMismatchException("Content has been tampered with, do not trust content: invalid padding length");

                trailBytes = (byte)(trailBytes % Constants.BLOCK_SIZE);

                m_length += trailBytes;
                m_extraDecryptedBytes.Append(decrypted.Slice(0, trailBytes == 0 ? Constants.BLOCK_SIZE : trailBytes));

                if (trailBytes != 0 && !m_ignorePaddingBytes)
                {
                    var paddingByte = (byte)(Constants.BLOCK_SIZE - trailBytes);
                    var paddingData = decrypted.Slice(trailBytes);
                    if (paddingData.ContainsAnyExcept(paddingByte))
                        throw new HashMismatchException("Content has been tampered with, do not trust content: invalid padding bytes");
                }
            }

            // If any decrypted bytes exists and can be returned, append them now
            var trailingCount = Math.Min(m_extraDecryptedBytes.Length, count);
            if (trailingCount > 0)
            {
                m_extraDecryptedBytes.Consume(trailingCount).CopyTo(buffer.AsSpan(offset));
                read += trailingCount;
                m_length += trailingCount;
            }

            // Verify the HMAC
            var hmacCalculated = m_hmac.Hash ?? throw new HashMismatchException("Unexpected missing hash value");
            var hmacRead = m_blockBuffer.Consume(Constants.HMAC_SIZE);
            if (!hmacCalculated.AsSpan().SequenceEqual(hmacRead))
                throw new HashMismatchException("Content has been tampered with, do not trust content: invalid HMAC");

            m_hmac.Dispose();
            m_cryptoTransform.Dispose();
        }

        return read;
    }

    /// <summary>
    /// Disposes the resources used by the DecryptingStream
    /// </summary>
    public void Dispose(bool disposing)
    {
        if (!m_leaveOpen)
            m_stream.Dispose();

        if (disposing)
        {
            m_cryptoTransform.Dispose();
            m_hmac.Dispose();
        }
    }
}
