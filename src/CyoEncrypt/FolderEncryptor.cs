using System;
using System.Threading.Tasks;

namespace CyoEncrypt
{
    public class FolderEncryptor : IEncryptor
    {
        private readonly byte[] _salt;
        private readonly bool _recurse;

        public FolderEncryptor(byte[] salt, bool recurse)
        {
            _salt = salt;
            _recurse = recurse;
        }

        public Task EncryptOrDecrypt(string pathname, string password)
        {
            throw new NotImplementedException();
        }
    }
}
