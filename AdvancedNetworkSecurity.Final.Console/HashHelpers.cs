using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AdvancedNetworkSecurity.Final.Console
{
    internal static class HashHelpers
    {
        public static string HashMD5(string input, bool upperCase = false)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                StringBuilder result = new StringBuilder(hashBytes.Length * 2);

                for (int i = 0; i < hashBytes.Length; i++)
                    result.Append(hashBytes[i].ToString(upperCase ? "X2" : "x2"));

                return result.ToString();
            }
        }

        public static string HashSHA256(string input, bool upperCase = false)
        {
            using (var md5 = System.Security.Cryptography.SHA256.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                StringBuilder result = new StringBuilder(hashBytes.Length * 2);

                for (int i = 0; i < hashBytes.Length; i++)
                    result.Append(hashBytes[i].ToString(upperCase ? "X2" : "x2"));

                return result.ToString();
            }
        }
    }
}
