// [CyoEncrypt.NET] FileEncryptor.cs

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
using System.Text;
using System.Threading.Tasks;

namespace CyoEncrypt
{
    public class FileEncryptor : IEncryptor
    {
        public static class Constants
        {
            public const string EncryptedExtension = ".encrypted";
        }

        private readonly byte[] _salt;
        private readonly IPassword _password;
        private readonly bool _quiet;

        public FileEncryptor(byte[] salt, IPassword password, bool quiet)
        {
            _salt = salt;
            _password = password;
            _quiet = quiet;
        }

        public async Task EncryptOrDecrypt(string pathname)
        {
            var isEncrypted = pathname.EndsWith(Constants.EncryptedExtension);

            var basePathname = GetBasePathname(pathname, isEncrypted);
            var outputPathname = GetOutputPathname(pathname, isEncrypted);

            byte[] iv = null;
            byte[] key = null;
            if (!isEncrypted && _password.Reencrypt)
            {
                var ivAndKey = _password.GetSavedKey(basePathname);
                if (ivAndKey.iv != null && ivAndKey.key != null)
                {
                    iv = ivAndKey.iv;
                    key = ivAndKey.key;
                }
            }
            if (iv == null || key == null)
            {
                var password = _password.GetPassword(pathname);
                var passwordBytes = Encoding.UTF8.GetBytes(password);
                iv = Crypto.CreateIv(passwordBytes, _salt);
                key = Crypto.CreateKey(passwordBytes, _salt);
            }

            await TransformFile(pathname, outputPathname, iv, key, isEncrypted);

            DeleteFile(pathname);

            if (!isEncrypted)
                _password.DeleteSavedKey(basePathname);
            else if (_password.Reencrypt)
                _password.SaveKey(basePathname, iv, key);
        }

        private string GetBasePathname(string pathname, bool isEncrypted)
        {
            return isEncrypted
                ? pathname.Substring(0, pathname.Length - Constants.EncryptedExtension.Length)
                : pathname;
        }

        private string GetOutputPathname(string pathname, bool isEncrypted)
        {
            var outputPathname = isEncrypted
                ? pathname.Substring(0, pathname.Length - Constants.EncryptedExtension.Length)
                : pathname + Constants.EncryptedExtension;

            if (File.Exists(outputPathname))
                throw new Exception($"Output file already exists: {Path.GetFileName(outputPathname)}");

            return outputPathname;
        }

        private async Task TransformFile(string inputPathname, string outputPathname, byte[] iv, byte[] key, bool isEncrypted)
        {
            using var aes = Crypto.CreateAes(iv, key);

            var fileLength = new FileInfo(inputPathname).Length;

            using var input = File.OpenRead(inputPathname);
            using var output = File.Create(outputPathname);

            var header = GetOrCreateHeader(input, output, isEncrypted, fileLength);

            var cryptoTransform = isEncrypted ? aes.CreateDecryptor() : aes.CreateEncryptor();

            await Crypto.Transform(input, output, isEncrypted, header.FileLength, cryptoTransform);

            ValidateOutputLength(output, isEncrypted, header);

            if (!_quiet)
                Console.WriteLine($"Successfully {(isEncrypted ? "decrypted" : "encrypted")}");
        }

        private static FileHeader GetOrCreateHeader(FileStream input, FileStream output, bool isEncrypted, long fileLength)
        {
            if (isEncrypted)
                return FileHeader.Parse(input);

            var header = new FileHeader { FileLength = fileLength };
            header.Write(output);
            return header;
        }

        private static void ValidateOutputLength(Stream output, bool isEncrypted, FileHeader header)
        {
            long expectedLength;

            if (isEncrypted)
                expectedLength = header.FileLength;
            else
            {
                var headerSize = FileHeader.Constants.HeaderLength;
                var blockSize = Crypto.Constants.BlockSize;
                expectedLength = headerSize + blockSize * ((header.FileLength / blockSize) + 1); //+1 because there's always an extra block
            }

            if (output.Length != expectedLength)
                throw new Exception($"{(isEncrypted ? "Decrypted" : "Encrypted")} file has unexpected length {output.Length}, expected {expectedLength}");
        }

        private static void DeleteFile(string pathname)
        {
            try
            {
                File.Delete(pathname);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WARNING: Unable to delete original file:\n{ex.Message}");
            }
        }
    }
}
