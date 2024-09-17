namespace CyoEncrypt.Extensions;

public static class StringExtensions
{
    public static string Pluralise(this string str, int count)
        => count != 1 ? $"{str}s" : str;
}