using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace AdvancedNetworkSecurity.Final.Console
{
    class Program
    {
        static List<string> hashes = new()
        {
            "65497CE4192CEADEDCD1EA132B28AF12",
            "CD68819DD93D394697CF9F115F4BEFEE",
            "649E4C20C12436402B848EB7A6D87E32",

            "C3CEBBB36A5A5D49E784BD4136133560",
            "FD815D238D21DEA12AD5167D4C913C8B",
            "83CFCE717CB9D6B3DA92CB2CFB4B37F1",

            "07C64EEC6612AEFBA0C53E0F23A0E1B27FCBFE0AD6BD4A461B391B347BB35161",
            "E377CF75B0570D60105F43E8CA7962D64B70D09A6532C50A8CFBDE8A1196208",
            "D6D7561C8221948187FAE3617C852F883247D925D6C198CF5E5E6DAE6D62EA49"
        };
        static void Main(string[] args)
        {

            var tasks = new List<Task>();
            //var dictionaries = new List<string>{
            //    "7-sorted.uniq",
            //    "8-sorted.uniq",
            //    "9-sorted.uniq",
            //    "10-sorted.uniq",
            //    "11-sorted.uniq",
            //    "12-sorted.uniq",
            //    "13-sorted.uniq",
            //    "14-sorted.uniq",
            //    "15+-sorted.uniq",
            //};

            var dictionaries = new List<string>{
                "realhuman_phill.txt",
                "10-million-combos.txt",
                "wl_jano_names_jargon.txt"
            };

            //tasks.Add(Task.Run(() => Dive("", 0)));
            //tasks.Add(Task.Run(() => PersianDive("", 0)));


            //foreach (var dic in dictionaries)
            //    tasks.Add(Task.Run(() => CheckInDictionary(dic)));

            //Task.WhenAll(tasks).GetAwaiter().GetResult();


            //dictionaries.Reverse();
            //foreach (var item in dictionaries)
            //    CheckInDictonaryAsync(item).GetAwaiter().GetResult();

            PersianDive2("", 0).GetAwaiter().GetResult();
            System.Console.WriteLine("Finish");

        }

        private static async Task CheckInDictonaryAsync(string dicName)
        {
            var lines = GetNumberOFLinesDictonary(dicName);

            int countLine = 0;
            while (true)
            {
                List<string> passwords = ReadLineDictonary(dicName, 50_000_000, countLine * 50_000_000);

                var tasks = new List<Task>();
                int getCount = 0;
                int n = passwords.Count;
                while (n > getCount)
                {
                    var privatePasswords = passwords.Take(n / 250);
                    passwords.RemoveRange(0, privatePasswords.Count());
                    getCount += n / 250;
                    tasks.Add(Task.Run(() =>
                    {
                        foreach (var password in privatePasswords)
                        {
                            CheckHasExists(password, HashHelpers.HashMD5, Guid.NewGuid().ToString() + "Result.txt");
                            CheckHasExists(password, HashHelpers.HashSHA256, Guid.NewGuid().ToString() + "ResultSha256.txt");

                        }
                    }));
                }
                passwords.Clear();
                await Task.WhenAll(tasks);
                countLine++;

                if (lines <= countLine * 50_000_000)
                    break;
            }


        }

        static void CheckInDictionary(string dicName)
        {
            var passwords = ReadDictonary(dicName);
            foreach (var password in passwords)
            {
                CheckHasExists(password, HashHelpers.HashMD5, dicName + "Result.txt");
                CheckHasExists(password, HashHelpers.HashSHA256, dicName + "Result.txt");

            }
        }
        private static string GetDictonaryDirectory(string dictonaryName)
            => Path.Combine(Directory.GetCurrentDirectory(), "Dictonaries", dictonaryName);
        private static List<string> ReadDictonary(string dictonaryName)
        {
            var path = GetDictonaryDirectory(dictonaryName);
            var fileContents = System.IO.File.ReadAllLines(path);

            return fileContents.Select(i => i.Split('\t')).SelectMany(i => i).Select(i => i.Trim()).Distinct().ToList();
        }

        private static List<string> ReadLineDictonary(string dictonaryName, int numberOfLines, int numberOfSkip)
        {
            var path = GetDictonaryDirectory(dictonaryName);
            var fileContents = System.IO.File.ReadLines(path);

            return fileContents.Skip(numberOfSkip).Take(numberOfLines).Select(i => i.Split('\t')).SelectMany(i => i).Select(i => i.Trim()).Distinct().ToList();
        }

        private static long GetNumberOFLinesDictonary(string dictonaryName)
        {
            var path = GetDictonaryDirectory(dictonaryName);
            return File.ReadLines(path).Count();
        }

        static int maxlength = 6;
        static string ValidChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+=";
        private static void Dive(string prefix, int level)
        {
            level += 1;
            foreach (char c in ValidChars)
            {
                CheckHasExists(prefix + c, HashHelpers.HashMD5, "Result.txt");
                CheckHasExists(prefix + c, HashHelpers.HashSHA256, "Result.txt");

                System.Console.WriteLine(prefix + c);
                //File.AppendAllLines(GetDictonaryDirectory("BruteForce.txt"), new string[] { prefix + c });
                if (level < maxlength)
                {
                    Dive(prefix + c, level);
                }
            }
        }

        static string PersianValidChars = "ابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهیآ" + "0123456789!@#$%^&*()_+=۰۱۲۳۴۵۶۷۸۹";
        private static void PersianDive(string prefix, int level)
        {
            level += 1;
            foreach (char c in PersianValidChars)
            {
                CheckHasExists(prefix + c, HashHelpers.HashMD5, Guid.NewGuid().ToString() + "ResultP.txt");
                CheckHasExists(prefix + c, HashHelpers.HashSHA256, Guid.NewGuid().ToString() + "ResultP.txt");

                System.Console.WriteLine(prefix + c);
                //File.AppendAllLines(GetDictonaryDirectory("BruteForcePersian.txt"), new string[] { prefix + c });
                if (level < maxlength)
                {
                    PersianDive(prefix + c, level);
                }
            }
        }
        private static Task PersianDive2(string prefix, int level)
        {
            var tasks = new List<Task>();
            level += 1;
            foreach (char c in PersianValidChars)
            {
                tasks.Add(Task.Run(() =>
                {
                    CheckHasExists(prefix + c, HashHelpers.HashMD5, Guid.NewGuid().ToString() + "ResultP.txt");
                    CheckHasExists(prefix + c, HashHelpers.HashSHA256, Guid.NewGuid().ToString() + "ResultP.txt");

                    System.Console.WriteLine(prefix + c);
                    //File.AppendAllLines(GetDictonaryDirectory("BruteForcePersian.txt"), new string[] { prefix + c });
                    if (level < maxlength)
                    {
                        PersianDive(prefix + c, level);
                    }
                }));
            }

            return Task.WhenAll(tasks);
        }

        private static void CheckHasExists(string password, Func<string, bool, string> hashFunc, string name)
        {
            var hash = hashFunc(password, true).ToUpper();

            if (hashes.Any(i => i.Equals(hash)))
            {
                File.AppendAllLines(GetDictonaryDirectory(name), new string[] { $"Hash: {hash} | Text: {password}" });
                System.Console.WriteLine($"Hash: {hash} | Text: {password}");
                System.Console.Beep();
            }
        }



    }


}
