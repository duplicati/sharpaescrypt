using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpAESCrypt.Unittest;

[TestClass]
public class BinaryCompatilibityTests
{
    // [TestMethod]
    public void TestBinaryCompatibility()
    {
        // Place the aescrypt binary in the same directory as the test project
        var path = Path.GetFullPath(Path.Combine(Path.Combine(System.Reflection.Assembly.GetExecutingAssembly().Location, "..", "..", "..", ".."), "aescrypt"));
        if (!File.Exists(path))
            throw new FileNotFoundException("aescrypt binary not found");

        var rnd = new Random();
        var failed = 0;

        // Test at boundaries and around the block/keysize margins
        foreach (var bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
            for (var i = Math.Max(0, bound - 6 * Constants.BLOCK_SIZE - 1); i <= bound + (6 * Constants.BLOCK_SIZE + 1); i++)
                using (var ms = new MemoryStream())
                {
                    var tmp = new byte[i];
                    rnd.NextBytes(tmp);
                    ms.Write(tmp.AsSpan(0));
                    if (!Unittest(path, ms))
                        failed++;
                }

        if (failed != 0)
            throw new Exception(string.Format("Failed with {0} tests", failed));
    }

    /// <summary>
    /// Helper function to perform a single test.
    /// </summary>
    /// <param name="path">The path to the aescrypt binary</param>
    /// <param name="input">The stream to test with</param>
    private static bool Unittest(string path, MemoryStream input)
    {
        const string PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#¤%&/()=?`*'^¨-_.:,;<>|";
        const int MIN_LEN = 1;
        const int MAX_LEN = 25;

        var reffile = Path.GetTempFileName();
        var encFile1 = Path.GetTempFileName();
        var encFile2 = Path.GetTempFileName();
        var decFile1 = Path.GetTempFileName();
        var decFile2 = Path.GetTempFileName();

        var tmpfiles = new string[] { reffile, encFile1, encFile2, decFile1, decFile2 };

        try
        {
            var rnd = new Random();
            var pwdchars = new char[rnd.Next(MIN_LEN, MAX_LEN)];
            for (int i = 0; i < pwdchars.Length; i++)
                pwdchars[i] = PASSWORD_CHARS[rnd.Next(0, PASSWORD_CHARS.Length)];

            input.Position = 0;
            using (var fs = new FileStream(reffile, FileMode.Create, FileAccess.Write))
                input.CopyTo(fs);


            var password = new string(pwdchars);

            AESCrypt.Encrypt(password, reffile, encFile1);
            ExternalEncrypt(path, password, reffile, encFile2);

            AESCrypt.Decrypt(password, encFile2, decFile1, new DecryptionOptions(IgnorePaddingBytes: true)); // Need to ignore padding for compatibility
            ExternalDecrypt(path, password, encFile1, decFile2);

            var refBytes = File.ReadAllBytes(reffile);
            var decBytes1 = File.ReadAllBytes(decFile1);
            var decBytes2 = File.ReadAllBytes(decFile2);

            if (refBytes.Length != decBytes1.Length || refBytes.Length != decBytes2.Length)
            {
                WriteProgressLine("FAILED: Length mismatch");
                return false;
            }

            var refhash = SHA256.HashData(File.ReadAllBytes(reffile));
            var dechash1 = SHA256.HashData(File.ReadAllBytes(decFile1));
            var dechash2 = SHA256.HashData(File.ReadAllBytes(decFile2));

            if (!refhash.AsSpan().SequenceEqual(dechash1) || !refhash.AsSpan().SequenceEqual(dechash2))
            {
                WriteProgressLine("FAILED: Hash mismatch");
                return false;
            }
        }
        catch (Exception ex)
        {
            WriteProgressLine("FAILED: " + ex.Message);
            return false;
        }
        finally
        {
            foreach (var file in tmpfiles)
                if (File.Exists(file))
                    File.Delete(file);
        }

        WriteProgressLine("OK!");
        return true;
    }

    private static void ExternalEncrypt(string path, string password, string inputfile, string outputfile)
    {
        using (var process = new System.Diagnostics.Process()
        {
            StartInfo = new(path, ["-e", "-p", password, "-o", outputfile, inputfile])
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        })
        {
            process.Start();
            process.WaitForExit();
            if (process.ExitCode != 0)
                throw new Exception($"External encrypt failed: {process.StandardError.ReadToEnd()}");
        }
    }

    private static void ExternalDecrypt(string path, string password, string inputfile, string outputfile)
    {
        using (var process = new System.Diagnostics.Process()
        {
            StartInfo = new(path, ["-d", "-p", password, "-o", outputfile, inputfile])
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        })
        {
            process.Start();
            process.WaitForExit();
            if (process.ExitCode != 0)
                throw new Exception($"External decrypt failed: {process.StandardError.ReadToEnd()}");
        }
    }

    private static void WriteProgressLine(string message)
    {
        Console.WriteLine(message);
    }
}
