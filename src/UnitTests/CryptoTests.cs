using CyoEncrypt;
using FluentAssertions;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public async Task GivenPlaintextWasEncrypted_WhenCiphertextIsDecrypted_ThenOutputShouldMatchPlaintext(int numBlocks)
        {
            var password = FillBuffer(1024);
            var salt = FillBuffer(1024);
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

        [Theory]
        [InlineData(0, "6UWXdE/L38fJliPkNdr1X75R0ge2y5Y5WDft/v9oVRs=")]
        [InlineData(1, "DvJkFKKAkI7g8Xkc1a94obw+WfFAP9+l76A5XRfpPV8=")]
        [InlineData(2, "MJWxw2ufBLVEQRiFDvF/etHEBO2uaL4Kc4WdXHGpgYo=")]
        [InlineData(4, "WjqCvayjH9C6YQogsJ29kegRieT/5Y6Rs3c5O9DLEoA=")]
        [InlineData(8, "RA7a1E9SxiqkW2KbFzQof6G2qkc3TdLu43N7vYXIfo4=")]
        [InlineData(16, "dc4tkuBzkANtNfBERvYA93KhBOz9zhsyzHMkEQVRmEM=")]
        [InlineData(32, "ipukZNVWgO37aOXhdAosD5zRrVI2yf99XGuamZVLEUg=")]
        [InlineData(64, "DXgkb+l257guCJTbnM90eS7/ka6KCWzb2vzJSCPSddo=")]
        public async Task WhenPlaintextIsEncrypted_ThenHashedCiphertextShouldMatchExpectedHash(int numBlocks, string expectedHash)
        {
            var password = Enumerable.Range(0, 1024).Select(x => (byte)x).ToArray();
            var salt = Enumerable.Range(1024, 2048).Select(x => (byte)x).ToArray();
            var aes = Crypto.CreateAes(password, salt);

            var plaintextLength = Crypto.Constants.BlockSize * numBlocks;
            var plaintextInput = Enumerable.Range(0, plaintextLength).Select(x => (byte)x).ToArray();
            var plaintextInputStream = new MemoryStream(plaintextInput);
            var ciphertextOutputStream = new MemoryStream();
            await Crypto.Transform(plaintextInputStream, ciphertextOutputStream, false, plaintextLength, aes.CreateEncryptor());

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
