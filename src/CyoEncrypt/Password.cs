// [CyoEncrypt.NET] Password.cs

// The MIT License (MIT)

// Copyright (c) 2020-2021 Graham Bull

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
using System.Text;

namespace CyoEncrypt
{
    public class Password : IPassword
    {
        public static class Constants
        {
            public const string Preamble = "CYO\x1";
        }

        private string _password;
        private readonly bool _noConfirm;
        private bool _confirmed;
        public bool Reencrypt { get; }

        public Password(string password, bool noConfirm, bool reencrypt)
        {
            _password = password;
            _noConfirm = noConfirm;
            Reencrypt = reencrypt;
        }

        public string GetPassword(string pathname)
        {
            if (string.IsNullOrEmpty(_password))
            {
                Console.Write("Password: ");
                _password = Console.ReadLine();
            }

            if (!_noConfirm && !_confirmed)
            {
                Console.Write("Confirm: ");
                var confirm = Console.ReadLine();
                if (_password != confirm)
                    throw new Exception("Passwords do not match!");
                _confirmed = true;
            }

            return _password;
        }

        public (byte[], byte[]) GetSavedKey(string pathname)
        {
            var passwordFile = MakePathnameForSavedPassword(pathname);
            if (!File.Exists(passwordFile))
                return (null, null);

            var fileInfo = new FileInfo(passwordFile);
            var expectedSize = GetExpectedSize();
            if (fileInfo.Length != expectedSize)
                return (null, null);

            var content = File.ReadAllBytes(passwordFile);
            using var memoryStream = new MemoryStream(content);
            using var binaryReader = new BinaryReader(memoryStream);
            var preamble = new string(binaryReader.ReadChars(Constants.Preamble.Length));
            if (!preamble.SequenceEqual(Constants.Preamble))
                return (null, null);
            var ivSize = binaryReader.ReadInt32();
            if (ivSize != Crypto.Constants.IvSize)
                return (null, null);
            var iv = binaryReader.ReadBytes(ivSize);
            var keySize = binaryReader.ReadInt32();
            if (keySize != Crypto.Constants.KeySize)
                return (null, null);
            var key = binaryReader.ReadBytes(keySize);
            return (iv, key);
        }

        public void SaveKey(string pathname, byte[] iv, byte[] key)
        {
            var passwordFile = MakePathnameForSavedPassword(pathname);
            if (File.Exists(passwordFile))
            {
                Console.WriteLine("File already exists!");
                return;
            }

            using var memoryStream = new MemoryStream();
            using var binaryWriter = new BinaryWriter(memoryStream);
            binaryWriter.Write(Constants.Preamble.ToCharArray());
            binaryWriter.Write(iv.Length);
            binaryWriter.Write(iv);
            binaryWriter.Write(key.Length);
            binaryWriter.Write(key);
            binaryWriter.Flush();
            var bytes = memoryStream.ToArray();
            File.WriteAllBytes(passwordFile, bytes);

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

        private string MakePathnameForSavedPassword(string pathname)
        {
            var filename = Path.GetFileName(pathname);
            var folder = Path.GetDirectoryName(pathname);
            return Path.Combine(folder, $".{filename}.cyoencrypt");
        }

        private static int GetExpectedSize()
            => Constants.Preamble.Length + (sizeof(int) * 2) + Crypto.Constants.IvSize + Crypto.Constants.KeySize;
    }
}
