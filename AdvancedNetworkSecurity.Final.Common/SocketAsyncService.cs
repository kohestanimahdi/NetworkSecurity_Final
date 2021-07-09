using System;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace AdvancedNetworkSecurity.Final.Common
{
    public class SocketAsyncService
    {

        int lenthByte = 512;
        TcpClient _tcpclient;
        byte[] mRx;

        public TcpClient TcpClient => _tcpclient;

        public void ConnectionToServer()
        {
            string ip;
            string portInput = "23000";
            int port;
            do
            {
                Console.Write("Please Enter Ip Address: ");
                ip = Console.ReadLine();
            } while (!IPAddress.TryParse(ip, out _));

            do
            {
                Console.Write("Please Enter Port Number: ");
                portInput = Console.ReadLine();
            } while (!Int32.TryParse(portInput, out port));


            StartConnectionToServerAsync(ip, port);

        }

        private void StartConnectionToServerAsync(string ip, int port)
        {

            IPAddress ipadrr = IPAddress.Parse(ip);

            _tcpclient = new TcpClient();
            _tcpclient.BeginConnect(ipadrr, port, onCompleteConnect, _tcpclient);

            Console.WriteLine($"Conected to {ip}:{port} successful.");

        }
        public void SendMessage(string message)
        {
            byte[] tx;

            try
            {
                if (!string.IsNullOrWhiteSpace(message) && _tcpclient != null && _tcpclient.Client.Connected)
                {
                    tx = Encoding.ASCII.GetBytes(message);
                    _tcpclient.GetStream().BeginWrite(tx, 0, tx.Length, onCompleteWriteToServer, _tcpclient);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message, "Error");
            }
        }
        public void CreateServer()
        {
            IPAddress ipadrr = ApplicationHelpers.GetMyIpAddress();
            int port = 23000;

            var _tcpListener = new TcpListener(ipadrr, port);
            _tcpListener.Start();

            _tcpListener.BeginAcceptTcpClient(onCompleteAcceptTcpClient, _tcpListener);

            Console.WriteLine($"IP: {ipadrr} | Port: {port}");
            Console.WriteLine("Waiting for connect to server");
        }
        private void onCompleteConnect(IAsyncResult iar)
        {
            TcpClient tcpc;
            try
            {
                tcpc = (TcpClient)iar.AsyncState;
                tcpc.EndConnect(iar);

                mRx = new byte[lenthByte];
                tcpc.GetStream().BeginRead(mRx, 0, mRx.Length, onCompleteReadFromServer, tcpc);

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message, "Error");
            }
        }
        private void onCompleteReadFromServer(IAsyncResult iar)
        {
            TcpClient tcpc;
            int ncountbyteresfromServer = 0;
            string res;

            try
            {
                tcpc = (TcpClient)iar.AsyncState;
                ncountbyteresfromServer = tcpc.GetStream().EndRead(iar);

                if (ncountbyteresfromServer == 0)
                {
                    Console.WriteLine("Connection Broken.");
                    return;
                }

                res = Encoding.ASCII.GetString(mRx, 0, ncountbyteresfromServer);

                Console.WriteLine(res);

                mRx = new byte[lenthByte];

                tcpc.GetStream().BeginRead(mRx, 0, mRx.Length, onCompleteReadFromServer, tcpc);

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message, "Error");
            }
        }
        private void onCompleteWriteToServer(IAsyncResult iar)
        {
            TcpClient tcpc;
            try
            {
                tcpc = (TcpClient)iar.AsyncState;
                tcpc.GetStream().EndWrite(iar);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message, "Error");
            }
        }
        private void onCompleteAcceptTcpClient(IAsyncResult iar)
        {
            TcpListener tcpl = (TcpListener)iar.AsyncState;
            try
            {
                _tcpclient = tcpl.EndAcceptTcpClient(iar);
                Console.WriteLine($"Client {_tcpclient.Client.RemoteEndPoint} Connected...");

                tcpl.BeginAcceptTcpClient(onCompleteAcceptTcpClient, tcpl);

                mRx = new byte[lenthByte];
                _tcpclient.GetStream().BeginRead(mRx, 0, mRx.Length, onCompleteReadFromTcpClient, _tcpclient);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }


        }
        private void onCompleteReadFromTcpClient(IAsyncResult iar)
        {
            TcpClient tcpc;
            int nCountReadBytes = 0;
            string strRec;
            try
            {
                tcpc = (TcpClient)iar.AsyncState;
                nCountReadBytes = tcpc.GetStream().EndRead(iar);

                if (nCountReadBytes == 0)
                {
                    Console.WriteLine("Client Disconnected.");
                    Console.Clear();
                    return;
                }

                strRec = Encoding.ASCII.GetString(mRx, 0, nCountReadBytes);

                Console.WriteLine(strRec);

                mRx = new byte[lenthByte];

                tcpc.GetStream().BeginRead(mRx, 0, mRx.Length, onCompleteReadFromTcpClient, tcpc);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

    }
}
