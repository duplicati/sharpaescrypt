namespace SharpAESCrypt;

/// <summary>
/// A simple byte buffer implementation based on an array and counters
/// </summary>
internal class ByteBuffer
{
    /// <summary>
    /// The buffer to store data in
    /// </summary>
    private readonly byte[] m_buffer;
    /// <summary>
    /// The number of bytes in the buffer
    /// </summary>
    private int m_count;
    /// <summary>
    /// The offset into the buffer
    /// </summary>
    private int m_offset;

    /// <summary>
    /// Constructs a new ByteBuffer instance
    /// </summary>
    /// <param name="size">The size of the buffer</param>
    public ByteBuffer(int size)
    {
        m_buffer = new byte[size];
    }

    /// <summary>
    /// The length of the buffer
    /// </summary>
    public int Length => m_count;

    /// <summary>
    /// The maximum buffer capacity
    /// </summary>
    public int Capacity => m_buffer.Length;
    /// <summary>
    /// The remaining capacity in the buffer
    /// </summary>
    public int RemainingCapacity => m_buffer.Length - m_count;
    /// <summary>
    /// The offset into the buffer
    /// </summary>
    public int Offset => m_offset;

    /// <summary>
    /// Access buffer as an array
    /// </summary>
    public byte[] Array => m_buffer;

    /// <summary>
    /// Optimizes the buffer by moving data to the start
    /// </summary>
    public void Optimize()
    {
        if (m_offset == 0)
        {
            return;
        }

        m_buffer.AsSpan(m_offset, m_count).CopyTo(m_buffer);
        m_offset = 0;
    }

    /// <summary>
    /// Appends data to the buffer
    /// </summary>
    /// <param name="count">The number of bytes to append</param>
    public void Appended(int count)
        => m_count += count;

    /// <summary>
    /// Appends data to the buffer
    /// </summary>
    /// <param name="data">The data to append</param>
    public void Append(ReadOnlySpan<byte> data)
    {
        if (data.Length + m_offset + m_count > m_buffer.Length && m_offset != 0)
            Optimize();

        // Append to the buffer
        data.CopyTo(m_buffer.AsSpan(m_offset + m_count));
        m_count += data.Length;
    }

    /// <summary>
    /// Resets the buffer
    /// </summary>
    public void Reset()
    {
        m_count = 0;
        m_offset = 0;
    }

    /// <summary>
    /// Consumes a number of bytes from the buffer
    /// </summary>
    /// <param name="count">The number of bytes to consume</param>
    public ReadOnlySpan<byte> Consume(int count)
    {
        var result = m_buffer.AsSpan(m_offset, count);
        m_offset += count;
        m_count -= count;
        if (m_count == 0)
            m_offset = 0;
        return result;
    }

    /// <summary>
    /// Reads data from a stream into the buffer, tries to fill as much as possible
    /// </summary>
    /// <param name="stream">The stream to read from</param>
    public int ReadIntoBuffer(Stream stream)
    {
        var read = stream.Read(m_buffer, m_offset, m_buffer.Length - m_offset);
        m_count += read;
        return read;
    }
}
