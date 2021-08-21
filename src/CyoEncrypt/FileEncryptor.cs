// [CyoEncrypt.NET] FileEncryptor.cs

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
        private readonly bool _quiet;

        public FileEncryptor(byte[] salt, bool quiet)
        {
            _salt = salt;
            _quiet = quiet;
        }

        public async Task EncryptOrDecrypt(string pathname, string password)
        {
            var isEncrypted = pathname.EndsWith(Constants.EncryptedExtension);

            string outputPathname;
            if (isEncrypted)
                outputPathname = pathname.Substring(0, pathname.Length - Constants.EncryptedExtension.Length);
            else
                outputPathname = pathname + Constants.EncryptedExtension;

            await TransformFile(pathname, outputPathname, password, isEncrypted);

            DeleteFile(pathname);
        }

        private async Task TransformFile(string inputPathname, string outputPathname, string password, bool isEncrypted)
        {
            if (File.Exists(outputPathname))
                throw new Exception($"Output file already exists: {Path.GetFileName(outputPathname)}");

            var passwordBytes = Encoding.UTF8.GetBytes(password);

            using var aes = Crypto.CreateAes(passwordBytes, _salt);

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
