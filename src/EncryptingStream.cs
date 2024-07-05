using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SharpAESCrypt;

/// <summary>
/// Stream interface for encrypting data
/// </summary>
public class EncryptingStream : Stream
{
    /// <summary>
    /// The underlying stream
    /// </summary>
    private readonly EncryptingStreamInternal m_internalStream;
    /// <summary>
    /// The stream to write to
    /// </summary>
    private readonly Stream m_stream;
    /// <summary>
    /// True if the stream should not be closed when this stream is closed
    /// </summary>
    private readonly bool m_leaveOpen;

    /// <summary>
    /// Constructs a new EncryptingStream instance, operating on the supplied stream
    /// </summary>
    /// <param name="password">The password used for encryption</param>
    /// <param name="stream">The stream to operate on, must be writeable</param>
    /// <param name="options">The file extension options to use</param>
    public EncryptingStream(string password, Stream stream, EncryptionOptions? options = null)
    {
        m_stream = stream;
        m_internalStream = new EncryptingStreamInternal(password, stream, options);
        m_leaveOpen = options?.LeaveOpen ?? false;
    }

    /// <summary>
    /// Flushes the final footer data to the stream
    /// </summary>
    public void FlushFinalBlock()
        => m_internalStream.FlushFinalBlock();

    /// <inheritdoc />
    public override bool CanRead => false;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => true;

    /// <inheritdoc />
    public override long Length => m_stream.Length;

    /// <inheritdoc />
    public override long Position
    {
        get => m_stream.Position;
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override void Flush() { }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
        => m_internalStream.Write(buffer, offset, count);

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        m_internalStream.Dispose(disposing);
        if (!m_leaveOpen)
            m_stream.Dispose();
        base.Dispose(disposing);
    }
}

/// <summary>
/// The internal implementation of the EncryptingStream.
/// This class prevents direct access and makes it simpler
/// to manage the public API
/// </summary>
internal class EncryptingStreamInternal
{
    /// <summary>
    /// The name inserted as the creator software in the extensions when creating output
    /// </summary>
    private static readonly string Extension_CreatedByIdentifier = $"SharpAESCrypt v{System.Reflection.Assembly.GetExecutingAssembly().GetName().Version}";

    /// <summary>
    /// The length of the data written so far
    /// </summary>
    private long m_length;

    /// <summary>
    /// True if the footer has been written, false otherwise. Used only for encryption.
    /// </summary>
    private bool m_hasFlushedFinalBlock = false;

    /// <summary>
    /// The file format version
    /// </summary>
    private readonly byte m_version;

    /// <summary>
    /// The encrypted stream to write to
    /// </summary>
    private readonly ICryptoTransform m_cryptoTransform;
    /// <summary>
    /// The HMAC instance
    /// </summary>
    private readonly HMAC m_hmac;
    /// <summary>
    /// The underlying stream
    /// </summary>
    private readonly Stream m_stream;
    /// <summary>
    /// The number of blocks to allocate in the buffer
    /// </summary>
    private const int BLOCK_IN_BUFFER = 1024; // BLOCK_SIZE is 16 bytes, so 16KiB
    /// <summary>
    /// The block buffer for partial block writes
    /// </summary>
    private readonly ByteBuffer m_blockBuffer = new ByteBuffer(Constants.BLOCK_SIZE * BLOCK_IN_BUFFER);

    /// <summary>
    /// Constructs a new AESCrypt instance, operating on the supplied stream
    /// </summary>
    /// <param name="password">The password used for encryption or decryption</param>
    /// <param name="stream">The stream to operate on, must be writeable</param>
    /// <param name="options">The options to use</param>
    public EncryptingStreamInternal(string password, Stream stream, EncryptionOptions? options = null)
    {
        //Basic input checks
        if (stream == null)
            throw new ArgumentNullException("stream");
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentNullException("password");
        if (!stream.CanWrite)
            throw new ArgumentException("The stream must be writeable", "stream");

        options ??= EncryptionOptions.Default;
        m_version = options.FileVersion;
        using var helper = new SetupHelper();

        // Create the Key using the password and generate a random IV
        var headerKey = helper.GenerateHeaderKeyAndIv(password);

        // v0 files use the header key directly for bulk encryption
        // Not recommended, not default, but supported for compatibility
        // v1+ files use a separate bulk encryption key and IV
        var bulkKey = options.FileVersion == 0
            ? new BulkEncryptionKey(headerKey.Key, headerKey.IV)
            : helper.GenerateBulkKey();

        // Write the header to the stream
        WriteFileHeader(stream, helper, headerKey, bulkKey, options);

        // Setup the HMAC and crypto
        m_stream = stream;
        m_hmac = helper.GetBulkHMAC(bulkKey);
        m_cryptoTransform = helper.CreateEncryptor(bulkKey);
    }

    /// <summary>
    /// Writes the header to the output stream
    /// </summary>
    /// <param name="stream">The stream to write to</param>
    /// <param name="helper">The setup helper instance</param>
    /// <param name="headerKey">The header encryption key</param>
    /// <param name="bulkEncryptionKey">The bulk encryption key</param>
    /// <param name="options">The encryption options to use</param>
    private static void WriteFileHeader(Stream stream, SetupHelper helper, HeaderEncryptionKey headerKey, BulkEncryptionKey bulkEncryptionKey, EncryptionOptions options)
    {
        stream.Write(Constants.MAGIC_HEADER.Span);
        stream.WriteByte(options.FileVersion);
        stream.WriteByte(0); //Reserved or length % 16
        if (options.FileVersion >= 2)
        {
            //Setup default extensions
            if (options.InsertCreatedByIdentifier)
                WriteExtension(stream, "CREATED_BY", System.Text.Encoding.UTF8.GetBytes(Extension_CreatedByIdentifier));

            if (options.InsertTimeStamp)
            {
                WriteExtension(stream, "CREATED_DATE", System.Text.Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("yyyy-MM-dd")));
                WriteExtension(stream, "CREATED_TIME", System.Text.Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("hh-mm-ss")));
            }

            if (options.AdditionalExtensions != null)
                foreach (var ext in options.AdditionalExtensions)
                    WriteExtension(stream, ext.Key, ext.Value);

            if (options.InsertPlaceholder)
                WriteExtension(stream, string.Empty, new byte[127]); //Suggested extension space  

            stream.Write([0, 0]); //No more extensions
        }

        stream.Write(headerKey.IV.Span);

        if (options.FileVersion != 0)
            stream.Write(helper.EncryptBulkAESKeyWithHMAC(headerKey, bulkEncryptionKey));
    }

    /// <summary>
    /// Writes an extension to the output stream, see:
    /// http://www.aescrypt.com/aes_file_format.html
    /// </summary>
    /// <param name="stream">The stream to write to</param>
    /// <param name="identifier">The extension identifier</param>
    /// <param name="value">The data to set in the extension</param>
    private static void WriteExtension(Stream stream, string identifier, byte[] value)
    {
        var name = System.Text.Encoding.UTF8.GetBytes(identifier);

        var sizebuf = new byte[2].AsSpan(); // Should be stackalloc
        BinaryPrimitives.WriteUInt16BigEndian(sizebuf, (ushort)(name.Length + 1 + value.Length));

        // Write [size, name, 0, value]
        stream.Write(sizebuf);
        stream.Write(name);
        stream.WriteByte(0);
        stream.Write(value);
    }

    /// <summary>
    /// Writes unencrypted data into an encrypted stream
    /// </summary>
    /// <param name="buffer">The data to write</param>
    /// <param name="offset">The offset into the buffer</param>
    /// <param name="count">The number of bytes to write</param>
    public void Write(byte[] buffer, int offset, int count)
    {
        // If we have not already started buffering, no need to do so now
        if (m_blockBuffer.Length > 0)
        {
            var toCopy = Math.Min(m_blockBuffer.RemainingCapacity, count);
            m_blockBuffer.Append(buffer.AsSpan(offset, toCopy));
            offset += toCopy;
            count -= toCopy;

            // If we filled the buffer, flush it, and process the rest of the input without buffering
            if (m_blockBuffer.Length == m_blockBuffer.Capacity)
            {
                WriteBlock(m_blockBuffer.Array, 0, m_blockBuffer.Length);
                m_blockBuffer.Reset();
            }
            else
            {
                // We have absorbed all data in the buffer with capacity to spare
                return;
            }
        }

        // Process data by encrypting into the buffer to avoid destroying the input buffer
        var bytesToWrite = Math.Min(m_blockBuffer.RemainingCapacity, count) / Constants.BLOCK_SIZE * Constants.BLOCK_SIZE;
        while (bytesToWrite > 0)
        {
            WriteBlock(buffer, offset, bytesToWrite);
            offset += bytesToWrite;
            count -= bytesToWrite;

            bytesToWrite = Math.Min(m_blockBuffer.RemainingCapacity, count) / Constants.BLOCK_SIZE * Constants.BLOCK_SIZE;
        }

        // If the input data is not divisble by the block size, buffer the remainder
        if (count > 0)
            m_blockBuffer.Append(buffer.AsSpan(offset, count));
    }

    /// <summary>
    /// Writes a block of data to the stream; this method destroys the <ref>m_blockBuffer</ref> contents
    /// </summary>
    /// <param name="buffer">The buffer to write from</param>
    /// <param name="offset">The offset into the buffer</param>
    /// <param name="count">The number of bytes to write</param>
    private void WriteBlock(byte[] buffer, int offset, int count)
    {
        m_cryptoTransform.TransformBlock(buffer, offset, count, m_blockBuffer.Array, 0);
        m_hmac.TransformBlock(m_blockBuffer.Array, 0, count, null, 0);
        m_length += count;
        m_stream.Write(m_blockBuffer.Array.AsSpan(0, count));
        m_blockBuffer.Reset();
    }


    /// <summary>
    /// Flushes any remaining data to the stream
    /// </summary>
    public void FlushFinalBlock()
    {
        if (!m_hasFlushedFinalBlock)
        {
            // Don't try again if this fails
            m_hasFlushedFinalBlock = true;
            var lastBlockLen = (byte)(m_blockBuffer.Length % Constants.BLOCK_SIZE);

            //Apply PaddingMode.PKCS7 manually, but without a padding block for empty last block
            if (lastBlockLen > 0)
            {
                // Pad the last block, we are guaranteed to have space for the block, 
                // as we fill the block with padding and the buffer is a multiple of the block size
                var padding = new byte[Constants.BLOCK_SIZE - lastBlockLen].AsSpan();
                padding.Fill((byte)padding.Length);
                m_blockBuffer.Append(padding);

                WriteBlock(m_blockBuffer.Array, 0, m_blockBuffer.Length);
                m_blockBuffer.Reset();
            }

            m_cryptoTransform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            m_hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            var hmac = (m_hmac.Hash ?? throw new CryptographicException("Unexpected missing hash value")).AsSpan();
            if (m_version == 0)
            {
                // v0 files have the HMAC at the end of the stream, but at counter in the header                    
                m_stream.Write(hmac);
                var pos = m_stream.Position;
                m_stream.Seek(Constants.MAGIC_HEADER.Length + 1, SeekOrigin.Begin);
                m_stream.WriteByte(lastBlockLen);
                m_stream.Seek(pos, SeekOrigin.Begin);
                m_stream.Flush();
            }
            else
            {
                // v1+ files have the last block size + HMAC at the end of the stream
                m_stream.WriteByte(lastBlockLen);
                m_stream.Write(hmac);
                m_stream.Flush();
            }

            m_cryptoTransform.Dispose();
        }
    }

    /// <summary>
    /// Disposes the resources used by the EncryptingStream
    /// </summary>
    public void Dispose(bool disposing)
    {
        if (!m_hasFlushedFinalBlock)
            FlushFinalBlock();

        if (disposing)
        {
            m_cryptoTransform.Dispose();
            m_hmac.Dispose();
        }
    }
}
