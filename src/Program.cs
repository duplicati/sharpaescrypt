namespace SharpAESCrypt;

/// <summary>
/// A simple commandline interface for the SharpAESCrypt library
/// </summary>
public static class Program
{
    /// <summary>
    /// A string displayed when the program is invoked without the correct number of arguments
    /// </summary>
    private static readonly string CommandlineUsage = string.Join(Environment.NewLine, new[] {
             "Usage: SharpAESCrypt e|d[o|c] <password> [<fromPath> [<toPath>]" +
            "",
             "Use 'e' or 'd' to specify operation: encrypt or decrypt." ,
             "Append an 'o' to the operation for optimistic mode. This will toggle compatibility mode, and leave partial/invalid files on disk." ,
             "Append a 'c' to the operation for compatibility mode. This will disable padding checks not in the original client." ,
            "",
             "If you ommit the fromPath or toPath, stdin/stdout are used insted, e.g.:" ,
             "  SharpAESCrypt e 1234 < file.jpg > file.jpg.aes" ,
            "",
             "Abnormal exit will return an errorlevel above 0 (zero):" ,
             "  4 - Password invalid" ,
             "  3 - HMAC Mismatch / altered data (also invalid password for version 0 files)" ,
             "  2 - Missing input stream / input file not found " ,
             "  1 - Any other cryptographic or IO exception",
        });

    /// <summary>
    /// Main function, used when compiled as a standalone executable
    /// </summary>
    /// <param name="args">Commandline arguments</param>
    public static void CommandLineMain(string[] args)
    {
        if (args.Length < 2)
        {
            Environment.ExitCode = 1;
            Console.Error.WriteLine(CommandlineUsage);
            return;
        }

        var encrypt = args[0].StartsWith("e", StringComparison.InvariantCultureIgnoreCase);
        var decrypt = args[0].StartsWith("d", StringComparison.InvariantCultureIgnoreCase);
        var optimisticMode = args[0].Contains('o', StringComparison.InvariantCultureIgnoreCase);
        var compatibilityMode = args[0].Contains('c', StringComparison.InvariantCultureIgnoreCase) | optimisticMode;

        var maxThreads = 1;
        for (var testFor = 1; testFor <= 4; testFor++)
            if (args[0].IndexOf((char)('0' + testFor)) >= 0) maxThreads = testFor;

        if (!(encrypt || decrypt))
        {
            Environment.ExitCode = 1;
            Console.Error.WriteLine("Invalid operation, must be (e)ncrypt or (d)ecrypt");
            return;
        }

        var inputname = (args.Length >= 3) ? args[2] : null;
        var outputname = (args.Length >= 4) ? args[3] : null;

        if (inputname != null && !File.Exists(inputname))
        {
            Environment.ExitCode = 2;
            Console.Error.WriteLine($"Input file not found: {inputname}");
            return;
        }


        try
        {
#if DEBUG
            var start = DateTime.Now;
#endif

            using (var inputstream = (inputname != null) ? File.OpenRead(inputname) : Console.OpenStandardInput())
            using (var outputstream = (outputname != null) ? File.Create(outputname) : Console.OpenStandardOutput())
                if (encrypt)
                    AESCrypt.Encrypt(args[1], inputstream, outputstream);
                else
                    AESCrypt.Decrypt(args[1], inputstream, outputstream, new DecryptionOptions(
                        IgnorePaddingBytes: compatibilityMode,
                        IgnoreFileLength: optimisticMode
                    ));
            Environment.ExitCode = 0;

#if DEBUG
            var dur = DateTime.Now - start;
            if (outputname != null) Console.WriteLine("Done! Crypting took about {0:0} ms", dur.TotalMilliseconds);
#endif

        }
        catch (Exception ex)
        {
            if (ex is WrongPasswordException)
                Environment.ExitCode = 4;
            if (ex is HashMismatchException)
                Environment.ExitCode = 3;
            else
                Environment.ExitCode = 1;

            Console.Error.WriteLine($"Error: {ex.Message}");
            // Delete output file if something went wrong
            if (!optimisticMode && outputname != null)
            {
                try { File.Delete(outputname); }
                catch { }
            }
        }
    }
}
