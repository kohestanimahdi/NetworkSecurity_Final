using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace AdvancedNetworkSecurity.Final.Common
{
    public static class ApplicationHelpers
    {
        private static string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        public static Random random = new Random();
        public static int KeyLenth = 2048;
        public static string GenerateNonce(int length)
        {
            var nonceString = new StringBuilder();
            for (int i = 0; i < length; i++)
            {
                nonceString.Append(validChars[random.Next(0, validChars.Length - 1)]);
            }

            return nonceString.ToString();
        }

        private static UnicodeEncoding ByteConverter = new UnicodeEncoding();

        public static string GenerateKey(string algorithm)
        {
            var type = algorithm.Split('_');

            if (type[0] == "AES")
                return GenerateAESKey();

            if (type[0] == "TripleDES")
                return GenerateTripleDESKey();

            throw new ArgumentException("Type is not valid");
        }

        public static CipherMode GetCipherMode(string cipherMode)
            => (CipherMode)Enum.Parse(typeof(CipherMode), cipherMode.ToUpper());

        public static byte[] ToByteArray(this string text)
            => ByteConverter.GetBytes(text);

        public static string ConvertToString(this byte[] plainTextBytes)
            => ByteConverter.GetString(plainTextBytes);
        public static string ConvertToBase64(this byte[] plainTextBytes)
            => Convert.ToBase64String(plainTextBytes);

        public static string ConvertToBase64(this string text)
        => text.ToByteArray().ConvertToBase64();

        public static string ConvertFromBase64(this string text)
        => Convert.FromBase64String(text).ConvertToString();


        public static string HashMD5(string input, bool upperCase = false)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
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
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                StringBuilder result = new StringBuilder(hashBytes.Length * 2);

                for (int i = 0; i < hashBytes.Length; i++)
                    result.Append(hashBytes[i].ToString(upperCase ? "X2" : "x2"));

                return result.ToString();
            }
        }


        private static byte[] IV = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        private static byte[] IV2 = { 1, 2, 3, 4, 5, 6, 7, 8 };
        public static string Encrypt(string text, string key, string algorithm = "AES_CBC")
        {
            byte[] bytes = Encoding.Unicode.GetBytes(text);
            //Encrypt

            SymmetricAlgorithm crypt;

            if (algorithm.Split('_')[0] == "TripleDES")
            {
                crypt = TripleDES.Create();
                crypt.BlockSize = 64;
                crypt.IV = IV2;

            }
            else
            {
                crypt = Aes.Create();
                crypt.BlockSize = 128;
                crypt.IV = IV;

            }

            crypt.Key = ByteConverter.GetBytes(key);

            crypt.Mode = GetCipherMode(algorithm.Split('_')[1]);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream =
                   new CryptoStream(memoryStream, crypt.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(bytes, 0, bytes.Length);
                }

                return Convert.ToBase64String(memoryStream.ToArray());
            }
        }

        public static string Decrypt(string cipherText, string key, string algorithm = "AES_CBC")
        {
            //Decrypt
            byte[] bytes = Convert.FromBase64String(cipherText);
            SymmetricAlgorithm crypt;

            if (algorithm.Split('_')[0] == "TripleDES")
            {
                crypt = TripleDES.Create();
                crypt.BlockSize = 64;
                crypt.IV = IV2;

            }
            else
            {
                crypt = Aes.Create();
                crypt.BlockSize = 128;
                crypt.IV = IV;

            }

            crypt.Key = ByteConverter.GetBytes(key);
            crypt.Mode = GetCipherMode(algorithm.Split('_')[1]);
            using (MemoryStream memoryStream = new MemoryStream(bytes))
            {
                using (CryptoStream cryptoStream =
                   new CryptoStream(memoryStream, crypt.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    byte[] decryptedBytes = new byte[bytes.Length];
                    cryptoStream.Read(decryptedBytes, 0, decryptedBytes.Length);
                    return Encoding.Unicode.GetString(decryptedBytes).Replace("\0", "");
                }
            }
        }

        public static IPAddress GetMyIpAddress()
        {
            IPAddress Ipv4 = null;
            try
            {
                var strThisHostName = System.Net.Dns.GetHostName();

                var thisHostDNSEntry = System.Net.Dns.GetHostEntry(strThisHostName);

                var AllIpsOfThisHost = thisHostDNSEntry.AddressList;

                for (int i = AllIpsOfThisHost.Length - 1; i > 0; i--)
                {
                    if (AllIpsOfThisHost[i].AddressFamily == AddressFamily.InterNetwork)
                    {
                        Ipv4 = AllIpsOfThisHost[i];
                        break;
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return Ipv4;
        }

        public static IEnumerable<string> GetCryptoModes()
        {
            var modes = Enum.GetNames(typeof(CipherMode));
            var crypto = new string[] { "AES", "TripleDES" };

            foreach (var c in crypto)
                foreach (var mode in modes)
                    if (!(mode == "CTS" || (c == "TripleDES" && mode == "OFB")))
                        yield return $"{c}_{mode}";
        }

        public static byte[] EncryptBytesToBytes_RSA(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                using (var RSA = new RSACryptoServiceProvider(KeyLenth))
                {
                    RSA.ImportParameters(RSAKey);
                    encryptedData = RSA.Encrypt(Data, DoOAEPPadding);
                }
                return encryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return new byte[0];
            }
        }

        static public byte[] EncryptStringToBytes_RSA(byte[] Data, RSACryptoServiceProvider RSA, bool DoOAEPPadding)
        {
            try
            {
                return RSA.Encrypt(Data, DoOAEPPadding);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return new byte[0];
            }
        }

        static public byte[] DecryptByteArrayFromBytes_RSA(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(KeyLenth))
                {
                    RSA.ImportParameters(RSAKey);
                    decryptedData = RSA.Decrypt(Data, DoOAEPPadding);
                }
                return decryptedData;

            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return new byte[0];
            }
        }

        static public string DecryptStringFromBytes_RSA(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(KeyLenth))
                {
                    RSA.ImportParameters(RSAKey);
                    decryptedData = RSA.Decrypt(Data, DoOAEPPadding);
                }
                return ByteConverter.GetString(decryptedData);

            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return string.Empty;
            }
        }

        private static string GenerateTripleDESKey()
        {
            var des = TripleDES.Create();
            des.GenerateIV();
            des.GenerateKey();
            return ByteConverter.GetString(des.Key);
        }

        private static string GenerateAESKey()
        {
            var des = Aes.Create();
            des.GenerateIV();
            des.GenerateKey();
            return ByteConverter.GetString(des.Key);
        }
        public static byte[] SignDataAsByteArray(string message, RSAParameters privateKey)
        {
            ASCIIEncoding byteConverter = new ASCIIEncoding();

            byte[] signedBytes;

            using (var rsa = new RSACryptoServiceProvider())
            {
                // Write the message to a byte array using ASCII as the encoding.
                byte[] originalData = byteConverter.GetBytes(message);

                try
                {
                    // Import the private key used for signing the message
                    rsa.ImportParameters(privateKey);

                    // Sign the data, using SHA512 as the hashing algorithm 
                    signedBytes = rsa.SignData(originalData, CryptoConfig.MapNameToOID("SHA512"));
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine(e.Message);
                    return null;
                }
                finally
                {
                    // Set the keycontainer to be cleared when rsa is garbage collected.
                    rsa.PersistKeyInCsp = false;
                }
            }
            // Convert the byte array back to a string message
            return signedBytes;
        }
        public static string SignData(string message, RSAParameters privateKey)
        => Convert.ToBase64String(SignDataAsByteArray(message, privateKey));

        public static bool VerifyData(string originalMessage, string signedMessage, RSAParameters publicKey)
        {
            bool success = false;
            using (var rsa = new RSACryptoServiceProvider())
            {
                ASCIIEncoding byteConverter = new ASCIIEncoding();

                byte[] bytesToVerify = byteConverter.GetBytes(originalMessage);
                byte[] signedBytes = Convert.FromBase64String(signedMessage);

                try
                {
                    rsa.ImportParameters(publicKey);

                    success = rsa.VerifyData(bytesToVerify, CryptoConfig.MapNameToOID("SHA512"), signedBytes);
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine(e.Message);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
            return success;
        }

        public static bool VerifyData(string originalMessage, string signedMessage, RSACryptoServiceProvider rsa)
        => VerifyData(originalMessage, signedMessage, rsa.ExportParameters(false));
    }

    public class RSAKeys
    {
        public static RSACryptoServiceProvider ImportPrivateKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider(ApplicationHelpers.KeyLenth);// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }

        public static RSACryptoServiceProvider ImportPublicKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider(ApplicationHelpers.KeyLenth);// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }

        public static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            return ExportPrivateKey(parameters);
        }
        public static string ExportPrivateKey(RSAParameters parameters)
        {
            StringWriter outputStream = new StringWriter();

            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN RSA PRIVATE KEY-----\n");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END RSA PRIVATE KEY-----");
            }

            return outputStream.ToString();
        }

        public static string ExportPublicKey(RSACryptoServiceProvider csp)
        {
            var parameters = csp.ExportParameters(false);
            return ExportPublicKey(parameters);
        }

        public static string ExportPublicKey(RSAParameters parameters)
        {
            StringWriter outputStream = new StringWriter();

            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN PUBLIC KEY-----\n");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END PUBLIC KEY-----");
            }

            return outputStream.ToString();
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
    }
}
