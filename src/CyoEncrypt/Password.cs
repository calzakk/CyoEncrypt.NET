// [CyoEncrypt.NET] Password.cs

// The MIT License (MIT)

// Copyright (c) 2020-2024 Graham Bull

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CyoEncrypt
{
    public class Password(string? password, bool noConfirm, bool reEncrypt, byte[] salt) : IPassword
    {
        private static class Constants
        {
            public const string Preamble = "CYO\x1";
        }

        private string? _password = password;
        private bool _confirmed;
        public bool ReEncrypt { get; } = reEncrypt;

        public byte[] GetPassword()
        {
            if (string.IsNullOrEmpty(_password))
            {
                Console.Write("Password: ");
                _password = Console.ReadLine()
                            ?? throw new Exception("Password cannot be empty");
            }

            if (!noConfirm && !_confirmed)
            {
                Console.Write("Confirm: ");
                var confirm = Console.ReadLine();
                if (_password != confirm)
                    throw new Exception("Passwords do not match!");
                _confirmed = true;
            }

            return Encoding.UTF8.GetBytes(_password);
        }
        
        public async Task<(byte[], byte[])?> GetSavedKey(string pathname)
        {
            var passwordFile = MakePathnameForSavedPassword(pathname);
            if (!File.Exists(passwordFile))
                return null;

            var fileInfo = new FileInfo(passwordFile);
            var expectedSize = GetExpectedSize();
            if (fileInfo.Length != expectedSize)
                return null;

            var content = await File.ReadAllBytesAsync(passwordFile);
            using var contentStream = new MemoryStream(content);
            var decryptedBytes = await Decrypt(contentStream, GetPasswordForSavedPassword(passwordFile));

            using var memoryStream = new MemoryStream(decryptedBytes);
            using var binaryReader = new BinaryReader(memoryStream);

            var preamble = new string(binaryReader.ReadChars(Constants.Preamble.Length));
            if (!preamble.SequenceEqual(Constants.Preamble))
                return null;

            var ivSize = binaryReader.ReadInt32();
            if (ivSize != Crypto.Constants.IvSize)
                return null;
            var iv = binaryReader.ReadBytes(ivSize);

            var keySize = binaryReader.ReadInt32();
            if (keySize != Crypto.Constants.KeySize)
                return null;
            var key = binaryReader.ReadBytes(keySize);

            return (iv, key);
        }

        public async Task SaveKey(string pathname, byte[] iv, byte[] key)
        {
            var passwordFile = MakePathnameForSavedPassword(pathname);
            if (File.Exists(passwordFile))
            {
                Console.WriteLine("File already exists!");
                return;
            }
            
            await using var memoryStream = new MemoryStream();
            await using var binaryWriter = new BinaryWriter(memoryStream);
            binaryWriter.Write(Constants.Preamble.ToCharArray());
            binaryWriter.Write(iv.Length);
            binaryWriter.Write(iv);
            binaryWriter.Write(key.Length);
            binaryWriter.Write(key);
            binaryWriter.Flush();
            var encryptedBytes = await Encrypt(memoryStream, GetPasswordForSavedPassword(passwordFile));
            await File.WriteAllBytesAsync(passwordFile, encryptedBytes);

            var attributes = File.GetAttributes(passwordFile);
            File.SetAttributes(passwordFile, attributes | FileAttributes.Hidden);
            Console.WriteLine("Password saved");
        }

        public void DeleteSavedKey(string pathname)
        {
            var passwordFile = MakePathnameForSavedPassword(pathname);
            if (!File.Exists(passwordFile))
                return;

            File.Delete(passwordFile);
            Console.WriteLine("Password deleted");
        }

        private static string MakePathnameForSavedPassword(string pathname)
        {
            var filename = Path.GetFileName(pathname);
            var folder = Path.GetDirectoryName(pathname);
            return Path.Join(folder, $".{filename}.cyoencrypt");
        }

        private static int GetExpectedSize()
        {
            var plaintext = Constants.Preamble.Length + (sizeof(int) * 2) + Crypto.Constants.IvSize + Crypto.Constants.KeySize;
            const int blockSize = Crypto.Constants.BlockSize;
            return ((plaintext + blockSize - 1) / blockSize) * blockSize;
        }

        private static byte[] GetPasswordForSavedPassword(string passwordFile)
            => Encoding.UTF8.GetBytes(Path.GetFileName(passwordFile));

        private Task<byte[]> Encrypt(Stream stream, byte[] passwordBytes)
            => Transform(stream, passwordBytes, true);

        private Task<byte[]> Decrypt(Stream stream, byte[] passwordBytes)
            => Transform(stream, passwordBytes, false);

        private async Task<byte[]> Transform(Stream stream, byte[] passwordBytes, bool encrypt)
        {
            stream.Position = 0;

            var iv = Crypto.CreateIv(passwordBytes, salt);
            var key = Crypto.CreateKey(passwordBytes, salt);
            using var aes = Crypto.CreateAes(iv, key);
            var cryptoTransform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();

            using var output = new MemoryStream();
            await Crypto.Transform(stream, output, false, cryptoTransform);
            return output.ToArray();
        } 
    }
}
