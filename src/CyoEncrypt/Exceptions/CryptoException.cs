using System;

namespace CyoEncrypt.Exceptions
{
    public class CryptoException : Exception
    {
        public CryptoException(string message) : base(message) { }
    }
}
