// [CyoEncrypt.NET] Crypto.cs

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

using CyoEncrypt.Exceptions;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Crypto_CipherMode = System.Security.Cryptography.CipherMode;
using Crypto_PaddingMode = System.Security.Cryptography.PaddingMode;

namespace CyoEncrypt
{
    public class Crypto
    {
        public static class Constants
        {
            public const int SaltSize = 1024;
            public const int SaltSizeInBits = SaltSize * 8;
            public const int HashSizeInBits = 512;
            public const int HashSize = HashSizeInBits / 8;
            public const int BlockSize = 16;
            public const int BlockSizeInBits = BlockSize * 8;
            public const int IvSize = BlockSize;
            public const int KeySize = 32;
            public const int KeySizeInBits = KeySize * 8;
            public const int Iterations = 1000;
            public const Crypto_CipherMode CipherMode = Crypto_CipherMode.CBC;
            public const Crypto_PaddingMode PaddingMode = Crypto_PaddingMode.PKCS7;
        }

        public static byte[] CreateSalt()
        {
            var salt = new byte[Constants.SaltSize];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        public static byte[] CreateIv(byte[] password, byte[] salt)
        {
            using var memoryStream = new MemoryStream();
            memoryStream.Write(password);
            memoryStream.Write(salt);
            memoryStream.Flush();
            var saltedPassword = memoryStream.GetBuffer();

            using var sha512 = SHA512.Create();
            var hashBytes = sha512.ComputeHash(saltedPassword);

            var iv = new byte[Constants.IvSize];
            Array.Fill<byte>(iv, 0x55);
            var index = 0;
            foreach (var b in hashBytes)
            {
                iv[index] ^= b;
                if (++index >= Constants.IvSize)
                    index = 0;
            }
            return iv;
        }

        public static byte[] CreateKey(byte[] password, byte[] salt)
        {
            using var deriver = new Rfc2898DeriveBytes(password, salt, Constants.Iterations, HashAlgorithmName.SHA512);
            return deriver.GetBytes(Constants.KeySize);
        }

        public static Aes CreateAes(byte[] password, byte[] salt)
        {
            var aes = Aes.Create();
            aes.IV = CreateIv(password, salt);
            aes.Key = CreateKey(password, salt);

            if (aes.KeySize != Constants.KeySizeInBits)
                throw new CryptoException("Unexpected key size");
            var maxKeySize = aes.LegalKeySizes[0].MaxSize;
            if (aes.KeySize != maxKeySize)
                throw new CryptoException("Not using maximum key size");

            if (aes.BlockSize != Constants.BlockSizeInBits)
                throw new CryptoException("Unexpected block size");
            var maxBlockSize = aes.LegalBlockSizes[0].MaxSize;
            if (aes.BlockSize != maxBlockSize)
                throw new CryptoException("Not using maximum block size");

            if (aes.Mode != Constants.CipherMode)
                throw new CryptoException("Not using CBC mode");

            if (aes.Padding != Constants.PaddingMode)
                throw new CryptoException("Not using PKCS #7 padding");

            return aes;
        }

        public static async Task Transform(Stream input, Stream output, bool isEncrypted, long plaintextLength, ICryptoTransform cryptoTransform)
        {
            try
            {
                using var cryptoStream = new CryptoStream(input, cryptoTransform, CryptoStreamMode.Read);
                await cryptoStream.CopyToAsync(output);

                await output.FlushAsync();
            }
            catch (Exception ex)
            {
                throw new CryptoException($"Unable to {(isEncrypted ? "decrypt" : "encrypt")} file: {ex.Message}");
            }
        }
    }
}
