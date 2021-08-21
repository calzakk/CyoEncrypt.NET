// [CyoEncrypt.NET] FileHeaderTests.cs

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
