﻿// [CyoEncrypt.NET] Arguments.cs

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
using System.Linq;

namespace CyoEncrypt;

public class Arguments
{
    public bool Help { get; private set; }
    public bool Recurse { get; private set; }
    public bool NoConfirm { get; private set; }
    public bool ReEncrypt { get; private set; }
    public string? Pathname { get; private set; }
    public string? Password { get; private set; }
    public string? Exclude { get; private set; }

    public static Arguments Parse(string[] args)
    {
        var arguments = new Arguments();

        foreach (var arg in args)
        {
            var larg = arg.ToLowerInvariant();

            if (MatchArg(larg, "help", 'h', '?'))
            {
                arguments.Help = true;
                return arguments;
            }
        }

        foreach (var arg in args)
        {
            var lowerArg = arg.ToLowerInvariant();

            if (MatchArg(lowerArg, "recurse", 'r'))
            {
                arguments.Recurse = true;
                continue;
            }

            if (MatchArg(lowerArg, "no-confirm"))
            {
                arguments.NoConfirm = true;
                continue;
            }

            if (MatchArg(lowerArg, "exclude", out var exclude))
            {
                arguments.Exclude = exclude;
                continue;
            }

            if (MatchArg(lowerArg, "reencrypt", 'e'))
            {
                arguments.ReEncrypt = true;
                continue;
            }

            if (!arg.StartsWith('-'))
            {
                if (string.IsNullOrEmpty(arguments.Pathname))
                {
                    arguments.Pathname = arg;
                    continue;
                }

                if (string.IsNullOrEmpty(arguments.Password))
                {
                    arguments.Password = arg;
                    continue;
                }
            }

            throw new ArgumentException($"Invalid argument: {arg}");
        }

        return arguments;
    }

    private static bool MatchArg(string arg, string option, params char[] abbr)
    {
        if (arg == $"--{option}")
            return true;

        if (abbr.Any(a => arg == $"-{a}"))
            return true;

        if (OperatingSystem.IsWindows() && abbr.Any(a => arg == $"/{a}"))
            return true;

        return false;
    }

    private static bool MatchArg(string arg, string option, out string? value)
    {
        var prefix = $"--{option}=";
        if (arg.StartsWith(prefix))
        {
            value = arg[prefix.Length..];
            return !string.IsNullOrWhiteSpace(value);
        }

        value = null;
        return false;
    }
}