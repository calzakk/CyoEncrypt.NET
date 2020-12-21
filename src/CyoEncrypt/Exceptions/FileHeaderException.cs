using System;

namespace CyoEncrypt.Exceptions
{
    public class FileHeaderException : Exception
    {
        public FileHeaderException(string message) : base(message) { }
    }
}
