// [CyoEncrypt.NET] Program.cs

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

using System;
using System.IO;
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
                        + "  CyoEncrypt <path> [<password>] [--no-confirm] [-r|--recurse] [--exclude=folder,...]");
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
                ? new FolderEncryptor(salt, arguments.Recurse, arguments.Exclude) as IEncryptor
                : new FileEncryptor(salt, false);

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
