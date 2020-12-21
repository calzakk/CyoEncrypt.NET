using CyoEncrypt;
using CyoEncrypt.Exceptions;
using FluentAssertions;
using System;
using System.IO;
using System.Security.Cryptography;
using Xunit;

namespace UnitTests
{
    public class FileHeaderTests
    {
        [Fact]
        public void GivenTheHeaderIsUninitialised_WhenTheHeaderIsOutput_ThenAnExceptionShouldBeThrown()
        {
            var header = new FileHeader();
            var outputStream = new MemoryStream();

            Action action = () => header.Write(outputStream);
            action.Should().Throw<FileHeaderException>();
        }

        [Fact]
        public void GivenAValidHeaderWasOutput_WhenTheHeaderIsParsed_ThenTheHeaderShouldBeParsed()
        {
            var header = new FileHeader { FileLength = 1024 };
            var stream = new MemoryStream();
            header.Write(stream);
            stream.Length.Should().Be(FileHeader.Constants.HeaderLength);
            stream.Position = 0;

            var headerRead = FileHeader.Parse(stream);
            headerRead.Should().BeEquivalentTo(header);
        }

        [Fact]
        public void GivenAnInvalidHeaderWasOutput_WhenTheHeaderIsParsed_ThenAnExceptionShouldBeThrown()
        {
            var invalidHeader = new byte[1024];
            RandomNumberGenerator.Fill(invalidHeader);
            var stream = new MemoryStream(invalidHeader);

            Action action = () => FileHeader.Parse(stream);
            action.Should().Throw<FileHeaderException>();
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(4)]
        public void GivenAHeaderWasOutputWithAnUnsupportVersion_WhenTheHeaderIsParsed_ThenAnExceptionShouldBeThrown(ushort versionMajor)
        {
            var header = new FileHeader
            {
                Preamble = FileHeader.Constants.Preamble,
                VersionMajor = versionMajor,
                VersionMinor = 0,
                FileLength = 1024,
                Reserved = FileHeader.Constants.Reserved,
                Sentinel = FileHeader.Constants.Sentinel
            };
            var stream = new MemoryStream();
            header.Write(stream);
            stream.Position = 0;

            Action action = () => FileHeader.Parse(stream);
            action.Should().Throw<FileHeaderException>();
        }
    }
}
