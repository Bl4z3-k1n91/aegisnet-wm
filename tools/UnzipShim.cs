using System;
using System.IO;
using System.IO.Compression;

public static class UnzipShim
{
    public static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "-Z1")
        {
            using (var archive = ZipFile.OpenRead(args[1]))
                foreach (var entry in archive.Entries)
                    Console.WriteLine(entry.FullName);
            return 0;
        }
        if (args.Length == 3 && args[0] == "-p")
        {
            using (var archive = ZipFile.OpenRead(args[1]))
            {
                var entry = archive.GetEntry(args[2]);
                if (entry == null) return 1;
                using (var input = entry.Open())
                using (var output = Console.OpenStandardOutput())
                    input.CopyTo(output);
            }
            return 0;
        }
        Console.Error.WriteLine("usage: unzip -Z1 ZIP | unzip -p ZIP MEMBER");
        return 2;
    }
}
