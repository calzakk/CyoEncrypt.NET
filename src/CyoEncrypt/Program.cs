using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CyoEncrypt
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            Arguments arguments;
            var password = string.Empty;
            try
            {
                arguments = Arguments.Parse(args);

                if (arguments.Help)
                {
                    Console.WriteLine("Usage:\n\n"
                        + "  CyoEncrypt <pathname> [<password>] [--no-confirm]\n"
                        + "  CyoEncrypt <path> [<password>] [--no-confirm] [-r|--recurse]");
                    return 2;
                }

                if (string.IsNullOrEmpty(arguments.Pathname))
                {
                    Console.WriteLine("Missing file or folder path");
                    return 2;
                }

                password = arguments.Password;
                if (string.IsNullOrEmpty(password))
                {
                    Console.Write("Password: ");
                    password = Console.ReadLine();
                }

                if (!arguments.NoConfirm)
                {
                    Console.Write("Confirm: ");
                    var confirm = Console.ReadLine();
                    if (password != confirm)
                    {
                        Console.WriteLine("Passwords do not match!");
                        return 3;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return 2;
            }

            var salt = GetSalt();

            var fileInfo = new FileInfo(arguments.Pathname);
            var encryptor = fileInfo.Attributes.HasFlag(FileAttributes.Directory)
                ? new FolderEncryptor(salt, arguments.Recurse) as IEncryptor
                : new FileEncryptor(salt);

            try
            {
                await encryptor.EncryptOrDecrypt(arguments.Pathname, password);
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: " + ex.Message);
                return 1;
            }
        }

        private static byte[] GetSalt()
        {
            const string subfolder = "CyoEncrypt";
            const string filename = "CyoEncrypt.data";

            var applicationData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var applicationDataPath = Path.Combine(applicationData, subfolder);
            var applicationDataPathname = Path.Combine(applicationDataPath, filename);
            if (File.Exists(applicationDataPathname))
                return File.ReadAllBytes(applicationDataPathname);

            var executingAssembly = System.Reflection.Assembly.GetExecutingAssembly().Location;
            var currentFolder = Path.GetDirectoryName(executingAssembly);
            var currentFolderPathname = Path.Combine(currentFolder, subfolder, filename);
            if (File.Exists(currentFolderPathname))
                return File.ReadAllBytes(currentFolderPathname);

            Console.WriteLine($"{filename} not found, creating...");

            var salt = Crypto.CreateSalt();

            Directory.CreateDirectory(applicationDataPath);
            File.WriteAllBytes(applicationDataPathname, salt);

            Console.WriteLine();
            Console.WriteLine("IMPORTANT: Ensure this file is securely backed up:");
            Console.WriteLine(applicationDataPathname);
            Console.WriteLine();
            Console.WriteLine("If it's lost, decryption will not be possible and");
            Console.WriteLine("encrypted files will not be recoverable!");
            Console.WriteLine();

            return salt;
        }
    }
}
