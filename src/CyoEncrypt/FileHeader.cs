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
            var binaryReader = new BinaryReader(stream);

            var header = new FileHeader
            {
                Preamble = new string(binaryReader.ReadChars(Constants.Preamble.Length)),
                VersionMajor = binaryReader.ReadUInt16(),
                VersionMinor = binaryReader.ReadUInt16(),
                FileLength = binaryReader.ReadInt64(),
                Reserved = binaryReader.ReadUInt64(),
                Sentinel = new string(binaryReader.ReadChars(Constants.Sentinel.Length))
            };

            if (!Validate(header))
                throw new FileHeaderException("File header is invalid or corrupt");

            return header;
        }

        private static bool Validate(FileHeader header)
        {
            if (!header.Preamble.SequenceEqual(Constants.Preamble))
                return false;

            if (header.VersionMajor != Constants.VersionMajor)
                throw new FileHeaderException($"Unsupported version: {header.VersionMajor}.{header.VersionMinor}");

            if (header.FileLength < 0)
                return false;

            if (header.Reserved != Constants.Reserved)
                return false;

            if (!header.Sentinel.SequenceEqual(Constants.Sentinel))
                return false;

            return true;
        }
    }
}
