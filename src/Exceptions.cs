using System.Security.Cryptography;

namespace SharpAESCrypt;

/// <summary> An exception raised to signal a hash mismatch on decryption </summary>
[Serializable]
public class HashMismatchException : CryptographicException
{
    /// <summary>
    /// Initializes a new instance of the HashMismatchException class.
    /// </summary>
    /// <param name="message">The error message to report.</param>
    public HashMismatchException(string message) : base(message) { }
}

/// <summary> An exception raised to signal that a wrong password was used </summary>
[Serializable]
public class WrongPasswordException : CryptographicException
{
    /// <summary>
    /// Initializes a new instance of the WrongPasswordException class.
    /// </summary>
    /// <param name="message">The error message to report.</param>
    public WrongPasswordException(string message) : base(message) { }
}
