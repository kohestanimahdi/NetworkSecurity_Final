using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;

namespace AdvancedNetworkSecurity.Final.Common
{
    public class SocketSyncService
    {
        public class Server
        {
            private readonly Socket listenfd;

            public Socket connfd;

            public Server()
            {
                //socket
                listenfd = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                //bind
                //The ip address and port number of the machine
                var ipAdr = ApplicationHelpers.GetMyIpAddress();
                var ipEp = new IPEndPoint(ipAdr, 32000);
                listenfd.Bind(ipEp);
            }
            public void StartListen()
            {
                //Listen
                listenfd.Listen(0);
                Console.WriteLine("[Server] started successfully");
                Console.WriteLine($"[Server] : {listenfd.LocalEndPoint} ");
                //Accept
                connfd = listenfd.Accept();
                Console.WriteLine($"[Server] Accept Connection from : {connfd.RemoteEndPoint}");

            }

            public string ReceiveMessage()
            {
                //Recv
                byte[] readBuff = new byte[2048];
                int count = connfd.Receive(readBuff);
                string str = System.Text.Encoding.UTF8.GetString(readBuff, 0, count);
                Console.WriteLine("[Server Receive]" + str);
                return str;
            }

            public byte[] ReceiveMessageAsByteArray()
            {
                //Recv
                byte[] readBuff = new byte[2048];
                int count = connfd.Receive(readBuff);
                return readBuff[0..count];
            }
            public void SendMessage(string str)
            {
                byte[] bytes = System.Text.Encoding.Default.GetBytes(str);
                connfd.Send(bytes);
            }
        }

        public class Client
        {
            public readonly Socket socket;
            public Client()
            {
                //Socket
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                Console.WriteLine(socket.LocalEndPoint);

            }

            public void ConnectToServer()
            {
                string ip;
                string portInput;
                int port = 32000;
                //do
                //{
                //    Console.Write("Please Enter Ip Address: ");
                //    ip = Console.ReadLine();
                //} while (!IPAddress.TryParse(ip, out _));

                //do
                //{
                //    Console.Write("Please Enter Port Number: ");
                //    portInput = Console.ReadLine();
                //} while (!Int32.TryParse(portInput, out port));

                //Connect
                //The ip address and port number of the server to be connected
                IPAddress ipAdr = ApplicationHelpers.GetMyIpAddress(); //IPAddress.Parse(ip);
                IPEndPoint ipEp = new IPEndPoint(ipAdr, port);
                socket.Connect(ipEp);
            }

            public string ReceiveMessage()
            {
                //Recv
                byte[] readBuff = new byte[2048];
                int count = socket.Receive(readBuff);
                var str = System.Text.Encoding.UTF8.GetString(readBuff, 0, count);
                Console.WriteLine(str);
                return str;
            }
            public void SendMessage(string str)
            {
                //Send
                byte[] bytes = System.Text.Encoding.Default.GetBytes(str);
                socket.Send(bytes);
            }
        }
    }
}
