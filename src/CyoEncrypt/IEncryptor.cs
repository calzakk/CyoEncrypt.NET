using System.Threading.Tasks;

namespace CyoEncrypt
{
    public interface IEncryptor
    {
        Task EncryptOrDecrypt(string pathname, string password);
    }
}
