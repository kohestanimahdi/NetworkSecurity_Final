using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using AdvancedNetworkSecurity.Final.Common;

namespace AdvancedNetworkSecurity.Final.Server
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

            // create server for socket
            var socketSyncService = new SocketSyncService.Server();

            // wait for a client connected to server
            socketSyncService.StartListen();

            // wait to receive first step of protocol from client
            var message = socketSyncService.ReceiveMessage();
            Thread.Sleep(10);

            // sned ack and server public key to client
            socketSyncService.SendMessage($"I'm server...|{message}|{RSAKeys.ExportPublicKey(publicKey)}");

            // wait to receive public key of client and crypto algorithms
            message = socketSyncService.ReceiveMessage();

            // public key of client
            RSACryptoServiceProvider clientPublicKey = RSAKeys.ImportPublicKey(message.Split('|')[0]);

            // all algorithms that receive from client
            var algorithms = message.Split('|')[1].Split(',');

            // select a random algorithm from abow algorithms
            string selectedAlgorithm = algorithms[ApplicationHelpers.random.Next(0, algorithms.Length)];
            Thread.Sleep(10);

            // send selected algorithm to client
            socketSyncService.SendMessage($"{selectedAlgorithm}");

            // wait to receive session key
            message = socketSyncService.ReceiveMessage();

            var messageBytes = Convert.FromBase64String(message.Split('|')[0]);

            // decrypt sign message with server private key
            var decryptByte = ApplicationHelpers.DecryptByteArrayFromBytes_RSA(messageBytes[0..256], privateKey, DoOAEPPadding);
            decryptByte = decryptByte.Concat(ApplicationHelpers.DecryptByteArrayFromBytes_RSA(messageBytes[256..],
                privateKey, DoOAEPPadding)).ToArray();

            // sign of client
            var sign = Convert.ToBase64String(decryptByte);

            // decrypt session key
            messageBytes = Convert.FromBase64String(message.Split('|')[1]);
            var sessionKey = ApplicationHelpers.DecryptStringFromBytes_RSA(messageBytes, privateKey, DoOAEPPadding);

            // decrypt nounce from server
            messageBytes = Convert.FromBase64String(message.Split('|')[2]);
            var nounce = ApplicationHelpers.DecryptStringFromBytes_RSA(messageBytes, privateKey, DoOAEPPadding);

            // create mac from session key
            var mac = ApplicationHelpers.HashMD5(sessionKey);

            // verify sign of client with session key, nounce and mac with client public key
            if (!ApplicationHelpers.VerifyData($"{nounce}|{sessionKey}|{mac}", sign, clientPublicKey))
            {
                Console.WriteLine("Invalid Sign");
                socketSyncService.connfd.Disconnect(true);
            }

            var signNounce = ApplicationHelpers.SignDataAsByteArray(nounce, privateKey);

            var encryptsignNounceBytes = ApplicationHelpers.EncryptBytesToBytes_RSA(signNounce[0..128],
                clientPublicKey.ExportParameters(false), DoOAEPPadding);

            var encryptString = encryptsignNounceBytes.Concat(ApplicationHelpers.EncryptBytesToBytes_RSA(signNounce[128..],
                clientPublicKey.ExportParameters(false), DoOAEPPadding)).ToArray().ConvertToBase64();

            Thread.Sleep(10);
            socketSyncService.SendMessage($"{encryptString}");

            message = socketSyncService.ReceiveMessage();
            if (message != "Let's Talk")
            {
                socketSyncService.connfd.Disconnect(true);
                return;
            }
            Thread.Sleep(1000);
            Console.Clear();
            Console.WriteLine($"Client {socketSyncService.connfd.RemoteEndPoint} authenticated successful");

            SendAndReceiveMessageStep(socketSyncService, sessionKey, selectedAlgorithm);


            Console.ReadLine();
        }

        static void SendAndReceiveMessageStep(SocketSyncService.Server socketSyncService, string sessionKey, string algorithm)
        {
            string userId;
            while (true)
            {
                var encryptedMessage = socketSyncService.ReceiveMessage();
                var message = ApplicationHelpers.Decrypt(encryptedMessage, sessionKey, algorithm);

                var contents = message.Split('|');
                if (contents[0] == "MESSAGE")
                {

                }
                else if (contents[0] == "REGISTER")
                {
                    userId = contents[2];
                }

            }
        }
    }
}
