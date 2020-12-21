using System;
using System.Linq;

namespace CyoEncrypt
{
    public class Arguments
    {
        public bool Help { get; set; } = false;
        public bool Recurse { get; set; } = false;
        public bool NoConfirm { get; set; } = false;
        public string Pathname { get; set; } = null;
        public string Password { get; set; } = null;

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
                var larg = arg.ToLowerInvariant();

                if (MatchArg(larg, "recurse", 'r'))
                {
                    arguments.Recurse = true;
                    continue;
                }

                if (MatchArg(larg, "no-confirm"))
                {
                    arguments.NoConfirm = true;
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

            return false;
        }
    }
}
