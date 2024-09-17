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
using System.Threading.Tasks;

namespace CyoEncrypt
{
    public class FileEncryptor(byte[] salt, IPassword password, bool quiet) : IEncryptor
    {
        public static class Constants
        {
            public const string EncryptedExtension = ".encrypted";
        }

        public async Task EncryptOrDecrypt(string pathname)
        {
            var isEncrypted = pathname.EndsWith(Constants.EncryptedExtension);

            var basePathname = GetBasePathname(pathname, isEncrypted);
            var outputPathname = GetOutputPathname(pathname, isEncrypted);

            byte[] iv = [];
            byte[] key = [];
            if (!isEncrypted && password.ReEncrypt)
            {
                var saved = await password.GetSavedKey(basePathname);
                if (saved is not null)
                    (iv, key) = (saved.Value.iv, saved.Value.key);
            }
            if (iv.Length == 0)
            {
                var passwordBytes = password.GetPassword();
                iv = Crypto.CreateIv(passwordBytes, salt);
                key = Crypto.CreateKey(passwordBytes, salt);
            }

            await TransformFile(pathname, outputPathname, iv, key, isEncrypted);

            DeleteFile(pathname);

            if (!isEncrypted)
                password.DeleteSavedKey(basePathname);
            else if (password.ReEncrypt)
                await password.SaveKey(basePathname, iv, key);
        }

        private static string GetBasePathname(string pathname, bool isEncrypted)
        {
            return isEncrypted
                ? pathname[..^Constants.EncryptedExtension.Length]
                : pathname;
        }

        private static string GetOutputPathname(string pathname, bool isEncrypted)
        {
            var outputPathname = isEncrypted
                ? pathname[..^Constants.EncryptedExtension.Length]
                : pathname + Constants.EncryptedExtension;

            if (File.Exists(outputPathname))
                throw new Exception($"Output file already exists: {Path.GetFileName(outputPathname)}");

            return outputPathname;
        }

        private async Task TransformFile(string inputPathname, string outputPathname, byte[] iv, byte[] key, bool isEncrypted)
        {
            using var aes = Crypto.CreateAes(iv, key);

            var fileLength = new FileInfo(inputPathname).Length;

            await using var input = File.OpenRead(inputPathname);
            await using var output = File.Create(outputPathname);

            var header = GetOrCreateHeader(input, output, isEncrypted, fileLength);

            var cryptoTransform = isEncrypted ? aes.CreateDecryptor() : aes.CreateEncryptor();

            await Crypto.Transform(input, output, isEncrypted, cryptoTransform);

            ValidateOutputLength(output, isEncrypted, header);

            if (!quiet)
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
                const int headerSize = FileHeader.Constants.HeaderLength;
                const int blockSize = Crypto.Constants.BlockSize;
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
