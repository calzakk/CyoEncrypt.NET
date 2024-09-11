// [CyoEncrypt.NET] Program.cs

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

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace CyoEncrypt
{
    public class Program
    {
        public static async Task<int> Main(string[] args)
        {
            Arguments arguments;
            try
            {
                arguments = Arguments.Parse(args);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return 1;
            }

            if (arguments.Help)
            {
                Console.WriteLine("Usage:\n"
                    + "  CyoEncrypt pathname [password] [options]\n"
                    + "\n"
                    + "Where:\n"
                    + $"  pathname         Specifies a file or {Folder}.\n"
                    + "  password         Encryption or decryption password.\n"
                    + "\n"
                    + "Options:\n"
                    + "  --no-confirm     Do not confirm the password.\n"
                    + "Options (files):\n"
                    + "  -e, --reencrypt  Remember the decryption password for subsequent re-encryption.\n"
                    + $"Options ({Folders}):\n"
                    + $"  -r, --recurse    Recurse into sub{Folders}.\n"
                    + $"  --exclude={Folder},...\n"
                    + $"                   Exclude named sub{Folders}.\n");
                return 2;
            }

            if (string.IsNullOrEmpty(arguments.Pathname))
            {
                Console.WriteLine("Missing file or folder path");
                return 1;
            }

            var salt = GetSalt();

            var password = new Password(arguments.Password, arguments.NoConfirm, arguments.ReEncrypt);

            var fileInfo = new FileInfo(arguments.Pathname);
            var dirInfo = new DirectoryInfo(arguments.Pathname);
            if (!fileInfo.Exists && !dirInfo.Exists)
            {
                Console.WriteLine($"File or {Folder} not found!");
                return 1;
            }

            if (ArgumentsAreIncompatible(arguments, dirInfo.Exists))
                return 1;

            var encryptor = dirInfo.Exists
                ? new FolderEncryptor(salt, password, arguments.Recurse, arguments.Exclude) as IEncryptor
                : new FileEncryptor(salt, password, false);

            try
            {
                await encryptor.EncryptOrDecrypt(arguments.Pathname);
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return 1;
            }
        }

        private static byte[] GetSalt()
        {
            const string subfolder = "CyoEncrypt";
            const string filename = "CyoEncrypt.data";

            var applicationData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var applicationDataPath = Path.Join(applicationData, subfolder);
            var applicationDataPathname = Path.Join(applicationDataPath, filename);
            if (File.Exists(applicationDataPathname))
                return File.ReadAllBytes(applicationDataPathname);

            var executingAssembly = System.Reflection.Assembly.GetExecutingAssembly().Location;
            var currentFolder = Path.GetDirectoryName(executingAssembly);
            var currentFolderPathname = Path.Join(currentFolder, subfolder, filename);
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

        private static bool ArgumentsAreIncompatible(Arguments arguments, bool isFolder)
        {
            var errors = new List<string>();

            if (isFolder)
            {
                if (arguments.ReEncrypt)
                    errors.Add($"--reencrypt cannot be used with {Folders}");
            }
            else
            {
                if (arguments.Recurse)
                    errors.Add("--recurse cannot be used with files");

                if (!string.IsNullOrEmpty(arguments.Exclude))
                    errors.Add("--exclude cannot be used with files");
            }

            foreach (var error in errors)
                Console.WriteLine(error);

            return errors.Count >= 1;
        }

        private static string Folder => OperatingSystem.IsWindows() ? "folder" : "directory";
        private static string Folders => OperatingSystem.IsWindows() ? "folders" : "directories";
    }
}
