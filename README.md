# SharpAESCrypt

A C# implementation of the [AESCrypt file format](https://www.aescrypt.com/).

This .NET AES Crypt package contains the C# class `SharpAESCrypt.SharpAESCrypt`, which provides file encryption and decryption using the [aescrypt file format](https://www.aescrypt.com/aes_file_format.html).

Version 2 of the AES File Format is supported for reading and writing. Versions 0 and 1 are not verified, but there is code to read and write the formats.

# Downloads

You can [install SharpAESCrypt from NuGet](https://www.nuget.org/packages/SharpAESCrypt).

The library is targeting .NET8. For [versions supporting Mono and .NET4, use v1.3.4](https://www.nuget.org/packages/SharpAESCrypt.dll/1.3.4) with a [different codebase](https://github.com/kenkendk/sharpaescrypt).

# Usage

With a reference to `SharpAESCrypt`, the primary interface are static methods:

```C#
    using SharpAESCrypt;
    AESCrypt.Encrypt("password", "inputfile", "outputfile");
    AESCrypt.Decrypt("password", "inputfile", "outputfile");
    AESCrypt.Encrypt("password", inputStream, outputStream);
    AESCrypt.Decrypt("password", inputStream, outputStream);
```

For uses where a stream is required/prefered, streams can also be created by wrapping either output or input:

```C#
    var encStream = new EncryptingStream(password, outputStream);
    var decStream = new DecryptingStream(password, inputStream);
```

Remember to either call `Dispose()` or `FlushFinalBlock()` after using the stream.

# Options

Generally, it is recommended that only the default options are applied, but it is possible to toggle some options via the optional `options` parameter.

For encrypting, you can control the written fileversion and what headers to include (if using v2):

```C#
var options = new EncryptionOptions(
    InsertCreatedByIdentifier: true,
    InsertTimeStamp: true,
    InsertPlaceholder: true,
    FileVersion: AESCrypt.DEFAULT_FILE_VERSION,
    LeaveOpen: false,
    AdditionalExtensions = new Dictionary<string, byte[]> {
        { "aes", new byte[] { 0x41, 0x45, 0x53 } }
    }
);

SharpAESCrypt.Encrypt("password", "inputfile", "outputfile", options);
```

For decrypting you can toggle some compatibility options:

```C#
var options = new DecyptionOptions(
    MinVersion: 2,
    LeaveOpen: false,
    IgnorePaddingBytes: false,
    IgnoreFileLength: false
);

SharpAESCrypt.Decrypt("password", "inputfile", "outputfile"), options;
```

The option `IgnorePaddingBytes` can be set to `true` to skip a consistency check made by this library.
The consistency check counters a [length modification vulnerability in the original format](https://www.aescrypt.com/wishlist.html).
If you need to read files generated by another tool, you may need to toggle this option.
