using System;

namespace CyoEncrypt.Exceptions
{
    public class AesException : Exception
    {
        public AesException(string message) : base(message) { }
    }
}
