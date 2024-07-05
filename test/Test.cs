using System;
using System.IO;

using System.Threading.Tasks;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;

namespace SharpAESCrypt.Unittest;

[TestClass]
public class Test
{
	const int MIN_SIZE = 1024 * 5;
	const int MAX_SIZE = 1024 * 1024 * 100; //100MiB
	const int REPETIONS = 100;

	[TestMethod]
	public void TestVersions()
	{
		var rnd = new Random();
		var failed = 0;

		//Test each supported version
		for (var v = 0; v <= Constants.MAX_FILE_VERSION; v++)
		{
			var opts = new EncryptionOptions() { FileVersion = (byte)v };
			// Test at boundaries and around the block/keysize margins
			foreach (var bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
				for (var i = Math.Max(0, bound - 6 * Constants.BLOCK_SIZE - 1); i <= bound + (6 * Constants.BLOCK_SIZE + 1); i++)
					using (var ms = new MemoryStream())
					{
						var tmp = new byte[i];
						rnd.NextBytes(tmp);
						ms.Write(tmp.AsSpan(0));
						if (!Unittest($"Testing version {v} with length = {ms.Length} => ", ms, -1, false, opts))
							failed++;
					}
		}

		if (failed != 0)
			throw new Exception($"Failed with {failed} tests");
	}

	[TestMethod]
	public void TestVersionsAsync()
	{
		var rnd = new Random();
		var failed = 0;

		//Test each supported version
		for (var v = 0; v <= Constants.MAX_FILE_VERSION; v++)
		{
			var opts = new EncryptionOptions() { FileVersion = (byte)v };
			// Test at boundaries and around the block/keysize margins
			foreach (var bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
				for (var i = Math.Max(0, bound - 6 * Constants.BLOCK_SIZE - 1); i <= bound + (6 * Constants.BLOCK_SIZE + 1); i++)
					using (var ms = new MemoryStream())
					{
						var tmp = new byte[i];
						rnd.NextBytes(tmp);
						ms.Write(tmp.AsSpan(0));
						if (!UnittestAsync($"Testing version {v} with length = {ms.Length} => ", ms, opts).Result)
							failed++;
					}
		}

		if (failed != 0)
			throw new Exception($"Failed with {failed} tests");
	}

	[TestMethod]
	public void TestNonSeekable()
	{
		var rnd = new Random();
		var failed = 0;

		//Test each supported version with variable buffer lengths
		// Version 0 does not support this
		for (var v = 1; v <= Constants.MAX_FILE_VERSION; v++)
		{
			var opts = new EncryptionOptions() { FileVersion = (byte)v };
			// Test at boundaries and around the block/keysize margins
			foreach (var bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
				for (var i = Math.Max(0, bound - 6 * Constants.BLOCK_SIZE - 1); i <= bound + (6 * Constants.BLOCK_SIZE + 1); i++)
					using (var ms = new MemoryStream())
					{
						var tmp = new byte[i];
						rnd.NextBytes(tmp);
						ms.Write(tmp, 0, tmp.Length);
						if (!Unittest($"Testing non-seekable version {v} with length = {ms.Length}, variable buffer sizes => ", ms, i + 3, true, opts))
							failed++;
					}
		}

		if (failed != 0)
			throw new Exception($"Failed with {failed} tests");

	}

	[TestMethod]
	public void TestVariableLengths()
	{
		var rnd = new Random();
		var failed = 0;

		//Test each supported version with variable buffer lengths
		for (var v = 0; v <= Constants.MAX_FILE_VERSION; v++)
		{
			var opts = new EncryptionOptions() { FileVersion = (byte)v };
			// Test at boundaries and around the block/keysize margins
			foreach (var bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
				for (var i = Math.Max(0, bound - 6 * Constants.BLOCK_SIZE - 1); i <= bound + (6 * Constants.BLOCK_SIZE + 1); i++)
					using (var ms = new MemoryStream())
					{
						var tmp = new byte[i];
						rnd.NextBytes(tmp);
						ms.Write(tmp, 0, tmp.Length);
						if (!Unittest($"Testing version {v} with length = {ms.Length}, variable buffer sizes => ", ms, i + 3, false, opts))
							failed++;
					}
		}

		if (failed != 0)
			throw new Exception($"Failed with {failed} tests");
	}


	/// <summary>
	/// This test checks how decryption reacts to truncated data.
	/// It should always throw with some kind of exception.
	/// Worst cases could be to return any data (also empty) without error.
	/// </summary>
	[TestMethod]
	public void TestTruncatedDataDecryption()
	{
		var rnd = new Random();
		var failed = 0;

		var maxByteCount = 1 << 21; // must be larger than maximum test size below. 

		//Test each supported version with variable buffer lengths
		for (var v = 0; v <= Constants.MAX_FILE_VERSION; v++)
		{
			var opts = new EncryptionOptions() { FileVersion = (byte)v, LeaveOpen = true };
			using (var ms = new MemoryStream())
			{
				var tmp = new byte[maxByteCount];
				rnd.NextBytes(tmp);
				var pwd = new string(Enumerable.Repeat('a', 10).Select(c => (char)(c + rnd.Next(26))).ToArray());
				AESCrypt.Encrypt(pwd, new MemoryStream(tmp), ms, opts);
				var approxHeaderSize = ((int)ms.Length) - tmp.Length - Constants.HMAC_SIZE;

				// Test at boundaries and around the block/keysize margins
				var bounds = new int[] { 0, 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 };
				Array.Reverse(bounds);
				foreach (int bound in bounds)
				{
					var low = Math.Max(-approxHeaderSize, bound - 6 * Constants.BLOCK_SIZE - 1);
					var high = Math.Min((int)ms.Length, bound + (6 * Constants.BLOCK_SIZE + 1));
					for (var i = approxHeaderSize + high; i >= approxHeaderSize + low; i--)
					{
						ms.SetLength(i); // truncate input stream!
						for (var useThreads = 1; useThreads <= 4; useThreads++)
						{
							ms.Position = 0;

							// Run the test in separate thread to detect races / deadlocks
							var runTest = Task.Run(() =>
							{
								Console.Write($"Testing version {v} with truncated stream length = {ms.Length}, using {useThreads} Thread(s) and variable buffer sizes => ");
								try
								{
									UnitStreamDecrypt(pwd, ms, new MemoryStream(tmp), 256);
									Console.WriteLine("FAILED: Truncated stream accepted.");
									return false;
								}
								catch
								{
									Console.WriteLine("OK!");
									return true;
								}
							});

							runTest.Wait(TimeSpan.FromSeconds(300));
							if (!runTest.IsCompleted)
							{
								Console.WriteLine("FAILED: A test timed out.");
								throw new Exception("A test timed out.");
							}
							else if (!runTest.Result)
								failed++;
						}
					}
				}

			}
		}

		if (failed != 0)
			throw new Exception($"Failed with {failed} tests");
	}

	[TestMethod]
	[TestCategory("Bulk")]
	/// <summary>
	/// This is a test that just runs a lot of tests with random data, trying to catch any edge cases.
	/// </summary>
	public void TestBulkRuns()
	{
		var rnd = new Random();
		var failed = 0;

		var opts = new EncryptionOptions() { FileVersion = Constants.MAX_FILE_VERSION };
		for (var i = 0; i < REPETIONS; i++)
		{
			using (MemoryStream ms = new MemoryStream())
			{
				var tmp = new byte[rnd.Next(MIN_SIZE, MAX_SIZE)];
				var f = rnd.Next(2) == 0;
				rnd.NextBytes(tmp);
				ms.Write(tmp, 0, tmp.Length);
				if (!Unittest($"Testing bulk {1} of {REPETIONS} with length = {ms.Length} => ", ms, 4096, f, opts))
					failed++;
			}
		}

		if (failed != 0)
			throw new Exception($"Failed with {failed} tests");
	}


	/// <summary>
	/// Helper function to perform a single test.
	/// </summary>
	/// <param name="message">A message printed to the console</param>
	/// <param name="input">The stream to test with</param>
	/// <param name="useRndBufSize">Option to use varying buffer sizes for each call</param>
	/// <param name="useNonSeekable">Flag to toggle use of a non-seekable stream</param>
	/// <param name="encryptionOptions">The encryption options to use</param>
	private static bool Unittest(string message, MemoryStream input, int useRndBufSize, bool useNonSeekable, EncryptionOptions encryptionOptions)
	{
		Console.Write(message);

		const string PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#¤%&/()=?`*'^¨-_.:,;<>|";
		const int MIN_LEN = 1;
		const int MAX_LEN = 25;

		try
		{
			var rnd = new Random();
			var pwdchars = new char[rnd.Next(MIN_LEN, MAX_LEN)];
			for (int i = 0; i < pwdchars.Length; i++)
				pwdchars[i] = PASSWORD_CHARS[rnd.Next(0, PASSWORD_CHARS.Length)];

			input.Position = 0;

			using (var enc = new MemoryStream())
			using (var dec = new MemoryStream())
			using (var nenc = useNonSeekable ? (Stream)new NonSeekableStream(enc) : enc)
			using (var ndec = useNonSeekable ? (Stream)new NonSeekableStream(dec) : dec)
			{
				AESCrypt.Encrypt(new string(pwdchars), input, nenc, encryptionOptions with { LeaveOpen = true });

				// 1st pass: test with wrong password if version > 0
				enc.Position = 0;
				try
				{
					if (encryptionOptions.FileVersion > 0)
					{
						AESCrypt.Decrypt("!WRONG_PASSWORD!", nenc, dec, new DecryptionOptions(LeaveOpen: true, MinVersion: encryptionOptions.FileVersion));
						throw new InvalidOperationException("Wrong password not detected.");
					}
				}
				catch (WrongPasswordException)
				{ }


				// 2nd Pass: data ok
				enc.Position = 0;
				if (useRndBufSize <= 0)
					AESCrypt.Decrypt(new string(pwdchars), nenc, dec, new DecryptionOptions(LeaveOpen: true, MinVersion: encryptionOptions.FileVersion));
				else
					UnitStreamDecrypt(new string(pwdchars), nenc, dec, useRndBufSize);
				dec.Position = 0;
				input.Position = 0;

				if (dec.Length != input.Length)
					throw new Exception($"Length differ {dec.Length} vs {input.Length}");

				for (int i = 0; i < dec.Length; i++)
					if (dec.ReadByte() != input.ReadByte())
						throw new Exception($"Streams differ at byte {i}");

				// 3rd pass: Change hash at end of file, and expect HashMismatch
				int changeHashAt = rnd.Next(Constants.HMAC_SIZE);
				enc.Position = enc.Length - changeHashAt - 1;
				int b = enc.ReadByte();
				enc.Position = enc.Length - changeHashAt - 1;
				enc.WriteByte((byte)(~b & 0xff));
				enc.Position = 0;
				try
				{
					if (useRndBufSize <= 0)
						AESCrypt.Decrypt(new string(pwdchars), nenc, dec, new DecryptionOptions(LeaveOpen: true, MinVersion: encryptionOptions.FileVersion));
					else
						UnitStreamDecrypt(new string(pwdchars), nenc, dec, useRndBufSize);
					throw new InvalidDataException("Mismatching HMAC not detected.");
				}
				catch (HashMismatchException)
				{ }

			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("FAILED: " + ex.Message);
			return false;
		}

		Console.WriteLine("OK!");
		return true;
	}

	/// <summary>
	/// Helper function to perform a single test.
	/// </summary>
	/// <param name="message">A message printed to the console</param>
	/// <param name="input">The stream to test with</param>
	/// <param name="useRndBufSize">Option to use varying buffer sizes for each call</param>
	/// <param name="useNonSeekable">Flag to toggle use of a non-seekable stream</param>
	/// <param name="encryptionOptions">The encryption options to use</param>
	private static async Task<bool> UnittestAsync(string message, MemoryStream input, EncryptionOptions encryptionOptions)
	{
		Console.Write(message);

		const string PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#¤%&/()=?`*'^¨-_.:,;<>|";
		const int MIN_LEN = 1;
		const int MAX_LEN = 25;

		try
		{
			var rnd = new Random();
			var pwdchars = new char[rnd.Next(MIN_LEN, MAX_LEN)];
			for (int i = 0; i < pwdchars.Length; i++)
				pwdchars[i] = PASSWORD_CHARS[rnd.Next(0, PASSWORD_CHARS.Length)];

			input.Position = 0;

			using (var enc = new MemoryStream())
			using (var dec = new MemoryStream())
			{
				await AESCrypt.EncryptAsync(new string(pwdchars), input, enc, encryptionOptions with { LeaveOpen = true });

				// 1st pass: test with wrong password if version > 0
				enc.Position = 0;
				try
				{
					if (encryptionOptions.FileVersion > 0)
					{
						await AESCrypt.DecryptAsync("!WRONG_PASSWORD!", enc, dec, new DecryptionOptions(LeaveOpen: true, MinVersion: encryptionOptions.FileVersion));
						throw new InvalidOperationException("Wrong password not detected.");
					}
				}
				catch (WrongPasswordException)
				{ }


				// 2nd Pass: data ok
				enc.Position = 0;
				await AESCrypt.DecryptAsync(new string(pwdchars), enc, dec, new DecryptionOptions(LeaveOpen: true, MinVersion: encryptionOptions.FileVersion));
				dec.Position = 0;
				input.Position = 0;

				if (dec.Length != input.Length)
					throw new Exception($"Length differ {dec.Length} vs {input.Length}");

				for (int i = 0; i < dec.Length; i++)
					if (dec.ReadByte() != input.ReadByte())
						throw new Exception($"Streams differ at byte {i}");

				// 3rd pass: Change hash at end of file, and expect HashMismatch
				int changeHashAt = rnd.Next(Constants.HMAC_SIZE);
				enc.Position = enc.Length - changeHashAt - 1;
				int b = enc.ReadByte();
				enc.Position = enc.Length - changeHashAt - 1;
				enc.WriteByte((byte)(~b & 0xff));
				enc.Position = 0;
				try
				{
					await AESCrypt.DecryptAsync(new string(pwdchars), enc, dec, new DecryptionOptions(LeaveOpen: true, MinVersion: encryptionOptions.FileVersion));
					throw new InvalidDataException("Mismatching HMAC not detected.");
				}
				catch (HashMismatchException)
				{ }

			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("FAILED: " + ex.Message);
			return false;
		}

		Console.WriteLine("OK!");
		return true;
	}

	/// <summary>
	/// For Unit testing: Decrypt a stream using the supplied password with changing (small) buffer sizes
	/// </summary>
	/// <param name="password">The password to decrypt with</param>
	/// <param name="input">The input stream</param>
	/// <param name="output">The output stream</param>
	/// <param name="bufferSizeSelect">The buffer size to use</param>
	private static void UnitStreamDecrypt(string password, Stream input, Stream output, int bufferSizeSelect)
	{
		var r = new Random();

		var partBufs = Math.Min(bufferSizeSelect, 1024);

		var buffers = new byte[partBufs][];
		for (int bs = 1; bs < partBufs; bs++)
			buffers[bs] = new byte[bs];

		buffers[0] = new byte[bufferSizeSelect];

		int a;
		using (input = new NonFulfillingReaderStream(input))
		{
			var c = new DecryptingStream(password, input, new DecryptionOptions(MinVersion: 0));
			do
			{
				var bufLen = r.Next(bufferSizeSelect) + 1;
				var useBuf = bufLen < partBufs ? buffers[bufLen] : buffers[0];
				a = c.Read(useBuf, 0, bufLen);
				output.Write(useBuf, 0, a);
			} while (a != 0);
		}
	}

	[TestMethod]
	public void TestReadHeader()
	{
		//Test each supported version
		var opts = new EncryptionOptions()
		{
			AdditionalExtensions = [new KeyValuePair<string, byte[]>("t1", [7, 8])],
			LeaveOpen = true
		};

		var data = new byte[] { 1, 2, 3, 4 };
		using (var ms = new MemoryStream())
		{
			AESCrypt.Encrypt("password", new MemoryStream(data), ms, opts);
			ms.Position = 0;
			var header = AESCrypt.ReadExtensions(ms).ToArray();
			var t1 = header.FirstOrDefault(h => h.Key == "t1");
			if (t1.Key != "t1" || !t1.Value.SequenceEqual(new byte[] { 7, 8 }))
				throw new Exception("Extension not found");
		}
	}
}

