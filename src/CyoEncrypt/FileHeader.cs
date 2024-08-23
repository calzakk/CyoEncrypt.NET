// [CyoEncrypt.NET] FileHeader.cs

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

using CyoEncrypt.Exceptions;
using System;
using System.IO;
using System.Linq;

namespace CyoEncrypt
{
    public class FileHeader
    {
        public static class Constants
        {
            public const string ErrorCorrupt = "File header is invalid or corrupt";
            public const int HeaderLength = 28;
            public const string Preamble = "CYO\0";
            public const ushort VersionMajor = 3;
            public const ushort VersionMinor = 0;
            public const ulong Reserved = 0;
            public const string Sentinel = "ZZZZ";
        }

        public string Preamble { get; init; } = Constants.Preamble;
        public ushort VersionMajor { get; init; } = Constants.VersionMajor;
        public ushort VersionMinor { get; init; } = Constants.VersionMinor;
        public long FileLength { get; set; } = -1;
        public ulong Reserved { get; init; } = Constants.Reserved;
        public string Sentinel { get; init; } = Constants.Sentinel;

        public void Write(Stream stream)
        {
            if (FileLength < 0)
                throw new FileHeaderException("File header has uninitialized length");

            var binaryWriter = new BinaryWriter(stream);
            binaryWriter.Write(Preamble.ToCharArray());
            binaryWriter.Write(VersionMajor);
            binaryWriter.Write(VersionMinor);
            binaryWriter.Write(FileLength);
            binaryWriter.Write(Reserved);
            binaryWriter.Write(Sentinel.ToCharArray());
            binaryWriter.Flush();

            if (stream.Length != Constants.HeaderLength)
                throw new FileHeaderException("File header has unexpected length");
        }

        public static FileHeader Parse(Stream stream)
        {
            var header = ParseHeader(stream);
            ValidateHeader(header);
            return header;
        }

        private static FileHeader ParseHeader(Stream stream)
        {
            try
            {
                var binaryReader = new BinaryReader(stream);

                return new FileHeader
                {
                    Preamble = new string(binaryReader.ReadChars(Constants.Preamble.Length)),
                    VersionMajor = binaryReader.ReadUInt16(),
                    VersionMinor = binaryReader.ReadUInt16(),
                    FileLength = binaryReader.ReadInt64(),
                    Reserved = binaryReader.ReadUInt64(),
                    Sentinel = new string(binaryReader.ReadChars(Constants.Sentinel.Length))
                };
            }
            catch
            {
                throw new FileHeaderException(Constants.ErrorCorrupt);
            }
        }

        private static void ValidateHeader(FileHeader header)
        {
            if (!header.Preamble.SequenceEqual(Constants.Preamble))
                throw new FileHeaderException(Constants.ErrorCorrupt);

            if (header.VersionMajor != Constants.VersionMajor)
            {
                var major = header.VersionMajor;
                var minor = header.VersionMinor;
                if (major >= 0x100)
                {
                    major = ConvertToLittleEndian(major);
                    minor = ConvertToLittleEndian(minor);
                }
                throw new FileHeaderException($"Unsupported version: {major}.{minor}");
            }

            if (header.FileLength < 0)
                throw new FileHeaderException(Constants.ErrorCorrupt);

            if (header.Reserved != Constants.Reserved)
                throw new FileHeaderException(Constants.ErrorCorrupt);

            if (!header.Sentinel.SequenceEqual(Constants.Sentinel))
                throw new FileHeaderException(Constants.ErrorCorrupt);
        }

        private static ushort ConvertToLittleEndian(ushort bigEndian)
        {
            var high = (bigEndian >> 8);
            var low = (bigEndian & 0xff);
            return (ushort)((low << 8) | high);
        }
    }
}
