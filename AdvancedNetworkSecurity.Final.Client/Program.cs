using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using AdvancedNetworkSecurity.Final.Common;

namespace AdvancedNetworkSecurity.Final.Client
{
    class Program
    {
        static void Main(string[] args)
        {

            bool DoOAEPPadding = true;

            var cryptoServiceProvider = new RSACryptoServiceProvider(ApplicationHelpers.KeyLenth);

            // create public and private key
            var privateKey = cryptoServiceProvider.ExportParameters(true);
            var publicKey = cryptoServiceProvider.ExportParameters(false);

            // get all algorithms for choose 
            var algorithms = ApplicationHelpers.GetCryptoModes().ToList();

            // create socket to connect to server
            var socketSyncService = new SocketSyncService.Client();
            socketSyncService.ConnectToServer();

            // send first step of protocol to server
            socketSyncService.SendMessage("Hello Server");

            //receive public key of server
            var message = socketSyncService.ReceiveMessage();
            var contents = message.Split('|');

            // public key of server
            RSACryptoServiceProvider serverPublicKey = RSAKeys.ImportPublicKey(contents[2]);
            Thread.Sleep(10);

            // send public key + all algorithms types 
            socketSyncService.SendMessage($"{RSAKeys.ExportPublicKey(publicKey)}|{string.Join(',', algorithms)}");
            string selectedAlgorithm = socketSyncService.ReceiveMessage();

            //create session key
            var sessionKey = ApplicationHelpers.GenerateKey(selectedAlgorithm);

            //create mounce
            var nounce = ApplicationHelpers.GenerateNonce(32);

            // create mac from session key
            var mac = ApplicationHelpers.HashMD5(sessionKey);

            // sign session key + nounce + mac with private key
            var signData = ApplicationHelpers.SignDataAsByteArray($"{nounce}|{sessionKey}|{mac}", privateKey);

            // encrypt sign + session key + nounce with server public key
            var encryptBytes = ApplicationHelpers.EncryptBytesToBytes_RSA(signData[0..128],
                serverPublicKey.ExportParameters(false), DoOAEPPadding);

            var encryptString = encryptBytes.Concat(ApplicationHelpers.EncryptBytesToBytes_RSA(signData[128..],
                serverPublicKey.ExportParameters(false), DoOAEPPadding)).ToArray().ConvertToBase64();

            encryptString += "|" + ApplicationHelpers.EncryptBytesToBytes_RSA(sessionKey.ToByteArray(),
                serverPublicKey.ExportParameters(false), DoOAEPPadding).ConvertToBase64();

            encryptString += "|" + ApplicationHelpers.EncryptBytesToBytes_RSA(nounce.ToByteArray(),
                serverPublicKey.ExportParameters(false), DoOAEPPadding).ConvertToBase64();

            Thread.Sleep(10);
            socketSyncService.SendMessage(encryptString);

            // receive nounce from server
            message = socketSyncService.ReceiveMessage();

            var messageBytes = Convert.FromBase64String(message);

            // decrypt sign message with server private key
            var decryptByte = ApplicationHelpers.DecryptByteArrayFromBytes_RSA(messageBytes[0..256],
                privateKey, DoOAEPPadding);

            decryptByte = decryptByte.Concat(ApplicationHelpers.DecryptByteArrayFromBytes_RSA(messageBytes[256..],
                privateKey, DoOAEPPadding)).ToArray();

            // sign of client
            var sign = Convert.ToBase64String(decryptByte);

            // verify server with nounce and sign
            if (!ApplicationHelpers.VerifyData(nounce, sign, serverPublicKey))
            {
                Console.WriteLine("Invalid Sign");
                socketSyncService.socket.Disconnect(true);
            }

            Thread.Sleep(10);
            socketSyncService.SendMessage("Let's Talk");
            Thread.Sleep(1000);
            Console.Clear();
            Console.WriteLine($"Authenticated to server successful");

            SendAndReceiveMessageStep(socketSyncService, sessionKey, selectedAlgorithm);

            Console.ReadLine();
        }

        static void SendAndReceiveMessageStep(SocketSyncService.Client socketSyncService, string sessionKey, string algorithm)
        {
            Thread.Sleep(50);
            var userId = Guid.NewGuid().ToString();
            var message = $"REGISTER|USER|{userId}";
            var encryptedMessage = ApplicationHelpers.Encrypt(message, sessionKey, algorithm);
            socketSyncService.SendMessage(encryptedMessage);

            var receiveErcrypted = socketSyncService.ReceiveMessage().ConvertFromBase64();
        }

    }
}
