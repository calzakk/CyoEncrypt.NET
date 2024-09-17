// [CyoEncrypt.NET] CryptoTests.cs

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

using CyoEncrypt;
using FluentAssertions;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests
{
    public class CryptoTests
    {
        private readonly SHA256 _sha256 = SHA256.Create();

        [Fact]
        public void WhenSaltIsCreated_ThenSaltShouldHaveValidSize()
        {
            var salt = Crypto.CreateSalt();

            salt.Length.Should().Be(Crypto.Constants.SaltSize);
        }

        [Fact]
        public void WhenIvIsCreated_ThenIvShouldHaveValidSize()
        {
            var password = FillBuffer(1024);
            var salt = FillBuffer(Crypto.Constants.SaltSize);
            var iv = Crypto.CreateIv(password, salt);

            iv.Length.Should().Be(Crypto.Constants.IvSize);
        }

        [Fact]
        public void WhenKeyIsCreated_ThenKeyShouldHaveValidSize()
        {
            var password = FillBuffer(1024);
            var salt = FillBuffer(Crypto.Constants.SaltSize);
            var key = Crypto.CreateKey(password, salt);

            key.Length.Should().Be(Crypto.Constants.KeySize);
        }

        [Fact]
        public void WhenAesIsInitialised_ThenAesShouldHaveValidSettings()
        {
            var password = FillBuffer(1024);
            var salt = FillBuffer(Crypto.Constants.SaltSize);
            var iv = Crypto.CreateIv(password, salt);
            var key = Crypto.CreateKey(password, salt);
            var aes = Crypto.CreateAes(iv, key);

            aes.IV.Length.Should().Be(Crypto.Constants.IvSize);
            aes.Key.Length.Should().Be(Crypto.Constants.KeySize);
            aes.Mode.Should().Be(Crypto.Constants.CipherMode);
            aes.Padding.Should().Be(Crypto.Constants.PaddingMode);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(4)]
        [InlineData(8)]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public async Task GivenPlaintextWasEncrypted_WhenCiphertextIsDecrypted_ThenOutputShouldMatchPlaintext(int numBlocks)
        {
            var password = FillBuffer(1024);
            var salt = FillBuffer(1024);
            var iv = Crypto.CreateIv(password, salt);
            var key = Crypto.CreateKey(password, salt);
            var aes = Crypto.CreateAes(iv, key);

            var plaintextLength = Crypto.Constants.BlockSize * numBlocks;
            var plaintextInput = FillBuffer(plaintextLength);
            var plaintextInputStream = new MemoryStream(plaintextInput);
            var ciphertextOutputStream = new MemoryStream();
            await Crypto.Transform(plaintextInputStream, ciphertextOutputStream, false, aes.CreateEncryptor());

            var outputSize = Crypto.Constants.BlockSize * (numBlocks + 1); //plus a final block
            var ciphertextOutput = ciphertextOutputStream.ToArray();
            ciphertextOutput.Length.Should().Be(outputSize);

            var ciphertextInputStream = new MemoryStream(ciphertextOutput);
            var decryptedOutputStream = new MemoryStream();
            await Crypto.Transform(ciphertextInputStream, decryptedOutputStream, true, aes.CreateDecryptor());

            var decryptedOutput = decryptedOutputStream.ToArray();
            decryptedOutput.Length.Should().Be(plaintextLength);
            decryptedOutput.Should().BeEquivalentTo(plaintextInput);
        }

        [Theory]
        [InlineData(0, "FrLvItpaGXumVR/96FhdX92sVLYi5u6xwLk2TVQDaoY=")]
        [InlineData(1, "8N33uOkddVjaYo+sLB/GmDsi6iNQ232odsv0uvluKJQ=")]
        [InlineData(2, "H4GPa5iZiSYKzpvjHXaf92WCvlaKPiC+Mr0X3Fi7kyU=")]
        [InlineData(4, "Ll9SZeTqs9NFOttvq+B9k+IIXrOveFbGTZi8jBNKoI0=")]
        [InlineData(8, "U4nceg95JlvJvRLEp0Laf5nwfVnofXhRQ+woUHW7hi8=")]
        [InlineData(16, "U9QDhMqPJ2xZw9gbrtqReV0aPA93AQNQrUXTsMN7MQ4=")]
        [InlineData(32, "X3hwy42Oap1E62NRG0pXPr8cRRdsdCYw8xi8E728xoM=")]
        [InlineData(64, "oQgOeLQUDyTkDFNaMzkvYw/Hz2t9j/hbZUgeW1GmBnA=")]
        public async Task WhenPlaintextIsEncrypted_ThenHashedCiphertextShouldMatchExpectedHash(int numBlocks, string expectedHash)
        {
            var password = Enumerable.Range(0, 1024).Select(x => (byte)x).ToArray();
            var salt = Enumerable.Range(0, 1024).Select(x => (byte)(x * 3)).ToArray();
            var iv = Crypto.CreateIv(password, salt);
            var key = Crypto.CreateKey(password, salt);
            var aes = Crypto.CreateAes(iv, key);

            var plaintextLength = Crypto.Constants.BlockSize * numBlocks;
            var plaintextInput = Enumerable.Range(0, plaintextLength).Select(x => (byte)x).ToArray();
            var plaintextInputStream = new MemoryStream(plaintextInput);
            var ciphertextOutputStream = new MemoryStream();
            await Crypto.Transform(plaintextInputStream, ciphertextOutputStream, false, aes.CreateEncryptor());

            var outputSize = Crypto.Constants.BlockSize * (numBlocks + 1); //plus a final block
            var ciphertextOutput = ciphertextOutputStream.ToArray();
            ciphertextOutput.Length.Should().Be(outputSize);

            var ciphertextInputStream = new MemoryStream(ciphertextOutput);
            var hash = await _sha256.ComputeHashAsync(ciphertextInputStream);
            Convert.ToBase64String(hash).Should().Be(expectedHash);
        }

        private static byte[] FillBuffer(int length)
        {
            var buffer = new byte[length];
            RandomNumberGenerator.Fill(buffer);
            return buffer;
        }
    }
}
