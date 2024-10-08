﻿// [CyoEncrypt.NET] FolderEncryptor.cs

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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CyoEncrypt.Extensions;

namespace CyoEncrypt;

public class FolderEncryptor(byte[] salt, IPassword password, bool recurse, string? exclude) : IEncryptor
{
    private readonly string[] _exclude = exclude?.Split(',') ?? [];

    public async Task EncryptOrDecrypt(string pathname)
    {
        var files = GetFiles(pathname);
        if (files.Count == 0)
        {
            Console.WriteLine("No files found!");
            return;
        }

        var encrypting = EnsureNoFileIsEncrypted(files);

        await EncryptOrDecryptFiles(files, encrypting);
    }

    private List<string> GetFiles(string pathname)
    {
        var searchOption = recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var files = Directory.GetFiles(pathname, "*.*", searchOption)
            .Select(Path.GetFullPath);

        if (_exclude.Length == 0)
            return files.ToList();

        var filtered = files.Where(file =>
        {
            var directory = Path.GetDirectoryName(file) ?? "";
            var folders = directory.Split(Path.DirectorySeparatorChar);
            return !folders.Any(folder => _exclude.Contains(folder));
        });
        return filtered.ToList();
    }

    private static bool EnsureNoFileIsEncrypted(List<string> files)
    {
        var plaintext = false;
        var encrypted = false;

        foreach (var file in files)
        {
            if (file.EndsWith(FileEncryptor.Constants.EncryptedExtension))
                encrypted = true;
            else
                plaintext = true;

            if (encrypted && plaintext)
                throw new Exception("Folder cannot contain both plaintext and encrypted files");
        }

        Debug.Assert(plaintext != encrypted);

        return plaintext;
    }

    private async Task EncryptOrDecryptFiles(List<string> files, bool encrypting)
    {
        var fileEncryptor = new FileEncryptor(salt, password, true);
        var remaining = files.Count;
        var completed = 0;
        var errors = new List<string>();
        var stopwatch = Stopwatch.StartNew();

        foreach (var file in files)
        {
            try
            {
                await fileEncryptor.EncryptOrDecrypt(file);
                ++completed;
            }
            catch
            {
                errors.Add(file);
            }

            --remaining;
            if (stopwatch.ElapsedMilliseconds > 1000)
            {
                Console.Write($"\r{remaining} \r");
                stopwatch.Restart();
            }
        }

        var fileOrFiles = "file".Pluralise(completed);
        var action = encrypting ? "encrypted" : "decrypted";
        Console.WriteLine($"{completed} {fileOrFiles} successfully {action}");

        if (errors.Count >= 1)
        {
            var errorFile = $"errors_{Guid.NewGuid()}.txt";
            await File.WriteAllLinesAsync(errorFile, errors);

            var errorOrErrors = "error".Pluralise(errors.Count);
            Console.WriteLine($"{errors.Count} {errorOrErrors} - see {errorFile}");
        }
    }
}