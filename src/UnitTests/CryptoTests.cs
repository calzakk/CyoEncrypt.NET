using CyoEncrypt;
using FluentAssertions;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests
{
    public class CryptoTests
    {
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
            var aes = Crypto.CreateAes(password, salt);

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
        public async Task GivenPlaintextWasEncrypted_WhenCiphertextIsDecrypted_ThenOutputShouldMatchPlaintext(int numBlocks)
        {
            var password = FillBuffer(1024);
            var salt = FillBuffer(Crypto.Constants.SaltSize);
            var aes = Crypto.CreateAes(password, salt);

            var plaintextLength = Crypto.Constants.BlockSize * numBlocks;
            var plaintextInput = FillBuffer(plaintextLength);
            var plaintextInputStream = new MemoryStream(plaintextInput);
            var ciphertextOutputStream = new MemoryStream();
            await Crypto.Transform(plaintextInputStream, ciphertextOutputStream, false, plaintextLength, aes.CreateEncryptor());

            var outputSize = Crypto.Constants.BlockSize * (numBlocks + 1); //plus a final block
            var ciphertextOutput = ciphertextOutputStream.ToArray();
            ciphertextOutput.Length.Should().Be(outputSize);

            var ciphertextInputStream = new MemoryStream(ciphertextOutput);
            var decryptedOutputStream = new MemoryStream();
            await Crypto.Transform(ciphertextInputStream, decryptedOutputStream, true, plaintextLength, aes.CreateDecryptor());

            var decryptedOutput = decryptedOutputStream.ToArray();
            decryptedOutput.Length.Should().Be(plaintextLength);
            decryptedOutput.Should().BeEquivalentTo(plaintextInput);
        }

        private static byte[] FillBuffer(int length)
        {
            var buffer = new byte[length];
            RandomNumberGenerator.Fill(buffer);
            return buffer;
        }
    }
}
