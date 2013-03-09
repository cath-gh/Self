//Date:     130309
//Usage:    IPSet for "1.2.3.4/30"
using System;
using System.ComponentModel;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace IPHelper
{
    public class IPSet
    {
        #region Fields
        private ushort _maskNum;
        private uint _Net;
        private uint _Gateway;
        private uint _DefaultIP;
        private uint _Broadcast;
        private uint _Mask;
        #endregion

        #region Properties
        public string Net { get; private set; }
        public string Gateway { get; private set; }
        public string DefaultIP { get; private set; }
        public string Broadcast { get; private set; }
        public string Mask { get; private set; }
        #endregion

        #region Constructor
        public IPSet(string ipStr)
        {
            if (ipStr == null) throw new ArgumentNullException("ipStr");
            string pattern = "(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])/(30|[1-2]\\d|[8-9])";
            Match m = Regex.Match(ipStr, pattern);
            if (!m.Success) throw new ArgumentException("ipStr");
            ushort[] numbers = new ushort[4];
            for (int i = 1, j = 0; i < 5; i++, j++)
                numbers[j] = Convert.ToUInt16(m.Groups[i].Value);
            _maskNum = Convert.ToUInt16(m.Groups[5].Value);

            uint ip_ori = (uint)(numbers[0] << 24 | numbers[1] << 16 | numbers[2] << 8 | numbers[3]);
            int shift = 32 - _maskNum;
            _Net = (ip_ori >> shift) << shift;
            _Gateway = _Net | 0x01;
            _Broadcast = _Net | (0xFFFFFFFF >> _maskNum);
            _DefaultIP = (ip_ori > _Gateway && ip_ori < _Broadcast) ? ip_ori : _Net | 0x02;
            _Mask = (0xFFFFFFFF >> shift) << shift;

            Net = MapUIntToString(_Net);
            Gateway = MapUIntToString(_Gateway);
            Broadcast = MapUIntToString(_Broadcast);
            DefaultIP = MapUIntToString(_DefaultIP);
            Mask = MapUIntToString(_Mask);
        }
        #endregion

        #region Private Mathods
        private static string MapUIntToString(uint ipUInt)
        {
            string[] ipSection = new string[4];
            ipSection[0] = (ipUInt >> 24).ToString();
            ipSection[1] = (ipUInt >> 16 & 0xFF).ToString();
            ipSection[2] = (ipUInt >> 8 & 0xFF).ToString();
            ipSection[3] = (ipUInt & 0xFF).ToString();
            return String.Join(".", ipSection);
        }

        private static uint MapStringToUInt(string ipStr)
        {
            string[] ipSection = ipStr.Split('.');
            return (uint)(Convert.ToUInt16(ipSection[0]) << 24 | Convert.ToUInt16(ipSection[1]) << 16 | Convert.ToUInt16(ipSection[2]) << 8 | Convert.ToUInt16(ipSection[3]));
        }
        #endregion

        #region Methods
        public static IPAddress ConvertToIPAddress(string ipStr)
        {
            return new IPAddress(MapStringToUInt(ipStr));
        }

        public bool Contains(string ipStr)
        {
            if (ipStr == null) throw new ArgumentNullException("ipStr");
            string pattern = "(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])/(30|[1-2]\\d|[8-9])";
            Match m = Regex.Match(ipStr, pattern);
            if (!m.Success) throw new ArgumentException("ipStr");
            uint ip = MapStringToUInt(ipStr);
            return ip >= _Net && ip <= _Broadcast;
        }
        #endregion

        #region Override Methods
        public override string ToString()
        {
            return String.Concat(Net, "/", _maskNum.ToString());
        }

        public string ToString(bool isFormat)
        {
            if (isFormat) return this.ToString();
            return String.Concat(DefaultIP, "/", _maskNum.ToString());
        }
        #endregion
    }

    public class PingStartedEventArgs : EventArgs
    {
        public IPHostEntry Entry { get; private set; }

        public string Message
        {
            get
            {
                if (Entry != null)
                {
                    if (Entry.AddressList != null) return String.Format("正在 Ping {0} [{1}] 具有 32 字节的数据:", Entry.HostName, Entry.AddressList[0].ToString());
                    return Entry.HostName;
                }
                return "No Message";
            }
        }

        public PingStartedEventArgs(IPHostEntry hostEntry)
        {
            Entry = hostEntry;
        }
    }

    public class PingReturnedEventArgs : EventArgs
    {
        public PingReply Reply { get; private set; }

        public string Message
        {
            get
            {
                if (Reply != null)
                {
                    if (Reply.Status != IPStatus.Success) return Reply.Status.ToString();
                    return String.Format("来自 {0} 的回复: 字节={1} 时间={2}ms TTL={3}", Reply.Address.ToString(), Reply.Buffer.Length.ToString(), Reply.RoundtripTime.ToString(), Reply.Options.Ttl.ToString());
                }
                return "No Message";
            }
        }

        public PingReturnedEventArgs(PingReply pingReply)
        {
            Reply = pingReply;
        }
    }

    public class PingFinishedEventArgs : EventArgs
    {
        public IPPing IPPing { get; private set; }
        public string Message
        {
            get
            {
                if (IPPing != null)
                {
                    string[] result = new string[4];
                    result[0] = String.Format("{0} 的 Ping 统计信息:", IPPing.Address.ToString());
                    result[1] = String.Format("\t数据包: 已发送 = {0}, 已接收 = {1}, 丢失 = {2}<{3} 丢失>", IPPing.Count.ToString(), IPPing.Received.ToString(), IPPing.Failed.ToString(), ((float)IPPing.Failed / IPPing.Count).ToString("p"));
                    result[2] = "往返行程的估计时间<以毫秒为单位>:";
                    result[3] = String.Format("\t最短 = {0}ms, 最长 = {1}ms, 平均 = {0}ms", IPPing.Min.ToString(), IPPing.Max.ToString(), IPPing.Avg.ToString());
                    return String.Join("\r\n", result);
                }
                return "No Message";
            }
        }

        public PingFinishedEventArgs(IPPing ping)
        {
            IPPing = ping;
        }
    }

    public class IPPing
    {
        #region Events
        public delegate void PingStartedHandler(PingStartedEventArgs startArgs);
        public event PingStartedHandler PingStarted;
        public delegate void PingReturnedHandler(PingReturnedEventArgs returnArgs);
        public event PingReturnedHandler PingReturned;
        public delegate void PingFinishedHandler(PingFinishedEventArgs finishArgs);
        public event PingFinishedHandler PingFinished;
        #endregion

        #region Statics
        private static int DefaultTimeOut = 5000;
        private static readonly byte[] DefaultBuffer = new byte[32];
        #endregion

        #region Fields
        private int _totalTime = 0;
        private int _maxTime = 0;
        private int _minTime = 5000;
        #endregion

        #region Properties
        public int Max { get { return _maxTime; } }
        public int Min { get { return _minTime; } }
        public int Avg { get { return Received == 0 ? 0 : _totalTime / Received; } }
        public IPAddress Address { get; private set; }
        public int Count { get; private set; }
        public int Received { get; private set; }
        public int Failed { get; private set; }
        #endregion

        #region Constructor
        public IPPing()
        {
            for (int i = 0; i < DefaultBuffer.Length; i++)
                DefaultBuffer[i] = (byte)((int)'a' + i % 23);
        }
        #endregion

        #region Methods
        public void Send(string dest, int count = 4, int ttl = 128)
        {
            if (dest == null) throw new ArgumentNullException("dest");
            if (count < 1 || ttl < 1) throw new ArgumentOutOfRangeException("count/ttl");
            try
            {
                IPHostEntry entry = Dns.GetHostEntry(dest);
                if (PingStarted != null) PingStarted(new PingStartedEventArgs(entry));
                Count = count;
                Address = entry.AddressList[0];
                PingOptions options = new PingOptions(ttl, true);
                for (int i = 0; i < count; i++)
                {
                    PingReply reply = new Ping().Send(Address, DefaultTimeOut, DefaultBuffer, options);
                    if (reply.Status != IPStatus.Success) Failed++;
                    else
                    {
                        int rTime = (int)reply.RoundtripTime;
                        _totalTime += rTime;
                        _maxTime = rTime > _maxTime ? rTime : _maxTime;
                        _minTime = rTime < _minTime ? rTime : _minTime;
                        Received++;
                    }
                    if (PingReturned != null) PingReturned(new PingReturnedEventArgs(reply));
                }
                if (PingFinished != null) PingFinished(new PingFinishedEventArgs(this));
            }
            catch (SocketException ex)
            {
                IPHostEntry entry = new IPHostEntry();
                entry.HostName = ex.Message;
                if (PingStarted != null) PingStarted(new PingStartedEventArgs(entry));
            }
        }
        
        public void SendAsync(string dest, int count = 4, int ttl = 128)
        {
            BackgroundWorker worker = new BackgroundWorker();
            Control.CheckForIllegalCrossThreadCalls = false;
            worker.DoWork += new DoWorkEventHandler((o, args) => { Send(dest, count, ttl); });
            worker.RunWorkerCompleted += new RunWorkerCompletedEventHandler((o, args) =>
                {
                    Control.CheckForIllegalCrossThreadCalls = true;
                    worker.Dispose();
                });
            worker.RunWorkerAsync();
        }

        public static PingReply SendOnce(IPAddress address, int ttl = 128)
        {
            if (address == null) throw new ArgumentNullException("dest");
            if (ttl < 1) throw new ArgumentOutOfRangeException("ttl");
            try
            {
                for (int i = 0; i < DefaultBuffer.Length; i++)
                    DefaultBuffer[i] = (byte)((int)'a' + i % 23);
                PingOptions options = new PingOptions(ttl, true);
                return new Ping().Send(address, DefaultTimeOut, DefaultBuffer, options);
            }
            catch { throw; }
        }
        #endregion
    }

    public class TracertStartedEventArgs : EventArgs
    {
        public IPHostEntry Entry { get; private set; }
        public int MaxHop { get; private set; }

        public string Message
        {
            get
            {
                if (Entry != null)
                {
                    if (Entry.AddressList != null) return String.Format("通过最多 {0} 个跃点跟踪\r\n到 {1} [{2}] 的路由:", MaxHop.ToString(), Entry.HostName, Entry.AddressList[0].ToString());
                    return Entry.HostName;
                }
                return "No Message";
            }
        }

        public TracertStartedEventArgs(IPHostEntry hostEntry, int maxHop)
        {
            Entry = hostEntry;
            MaxHop = maxHop;
        }
    }

    public class TracertReturnedEventArgs : EventArgs
    {
        public IPTracert Tracert { get; private set; }
        public int[] Time { get; private set; }

        public string Message
        {
            get
            {
                if (Tracert != null)
                {
                    if (Time == null) return String.Format("{0}\t*   \t*   \t*  \t{1}(请求超时)", Tracert.Hop.ToString(), Tracert.LastAddress.ToString());
                    return String.Format("{0}\t{1} ms\t{2} ms\t{3} ms\t{4}", Tracert.Hop.ToString(), Time[0].ToString(), Time[1].ToString(), Time[2].ToString(), Tracert.LastAddress.ToString());
                }
                return "No Message";
            }
        }

        public TracertReturnedEventArgs(IPTracert tracert, int[] time)
        {
            Tracert = tracert;
            Time = time;
        }
    }

    public class TracertFinishedEventArgs : EventArgs
    {
        public IPTracert IPTracert { get; private set; }
        public string Message
        {
            get
            {
                if (IPTracert != null) return String.Format("跟踪完成, 经过跃点 {0}, 最后一跳地址 {1}", IPTracert.Hop, IPTracert.LastAddress.ToString());
                return "No Message";
            }
        }

        public TracertFinishedEventArgs(IPTracert tracert)
        {
            IPTracert = tracert;
        }
    }

    public class IPTracert
    {
        #region Events
        public delegate void TracertStartedHandler(TracertStartedEventArgs replyArgs);
        public event TracertStartedHandler TracertStarted;
        public delegate void TracertReturnedHandler(TracertReturnedEventArgs replyArgs);
        public event TracertReturnedHandler TracertReturned;
        public delegate void TracertFinishedHandler(TracertFinishedEventArgs finishArgs);
        public event TracertFinishedHandler TracertFinished;
        #endregion

        #region Properties
        public int Hop { get; private set; }
        public bool IsReached { get; private set; }
        public IPAddress LastAddress { get; private set; }
        #endregion

        #region Constructor
        public IPTracert()
        {
            Hop = 0;
            IsReached = false;
        }
        #endregion

        #region Methods
        public void Tracert(string dest, int maxHop = 30)
        {
            if (dest == null) throw new ArgumentNullException("dest");
            if (maxHop < 1) throw new ArgumentOutOfRangeException("maxHop");
            try
            {
                IPHostEntry entry = Dns.GetHostEntry(dest);
                if (TracertStarted != null) TracertStarted(new TracertStartedEventArgs(entry, maxHop));
                IPAddress address = entry.AddressList[0];
                int[] time = new int[3];
                bool isTimeout = false;
                PingReply reply;
                IPAddress hopAddress = null;
                for (int i = 0; i < maxHop; i++)
                {
                    isTimeout = false;
                    int j = 0;
                    do
                    {
                        reply = IPPing.SendOnce(address, i + 1);
                        if (reply.Status != IPStatus.TimedOut) hopAddress = reply.Address;
                        else
                        {
                            time[j] = -1;
                            j++;
                        }
                    }
                    while (hopAddress == null && j < 3);
                    for (; j < 3; j++)
                    {
                        reply = IPPing.SendOnce(hopAddress);
                        if (reply.Status != IPStatus.TimedOut) time[j] = (int)reply.RoundtripTime;
                        else time[j] = -1;
                    }
                    Hop++;
                    LastAddress = hopAddress == null ? LastAddress : hopAddress;
                    if (time[0] == -1 || time[1] == -1 || time[2] == -1) isTimeout = true;
                    if (TracertReturned != null) TracertReturned(new TracertReturnedEventArgs(this, isTimeout ? null : time));
                    if (hopAddress.Equals(address))
                    {
                        IsReached = true; break;
                    }
                }
                if (TracertFinished != null) TracertFinished(new TracertFinishedEventArgs(this));
            }
            catch { throw; }
        }

        public void TracertAsync(string dest, int maxHop = 30)
        {
            BackgroundWorker worker = new BackgroundWorker();
            Control.CheckForIllegalCrossThreadCalls = false;
            worker.DoWork += new DoWorkEventHandler((o, args) => { Tracert(dest, maxHop); });
            worker.RunWorkerCompleted += new RunWorkerCompletedEventHandler((o, args) =>
            {
                Control.CheckForIllegalCrossThreadCalls = true;
                worker.Dispose();
            });
            worker.RunWorkerAsync();
        }
        #endregion
    }

    public static class Utilities
    {
        public static void SetIP(string ip, string mask, string gateway, string dns)
        {
            ManagementClass mc = new ManagementClass("Win32_NetworkAdapterConfiguration");
            ManagementObjectCollection moc = mc.GetInstances();
            foreach (ManagementObject mo in moc)
            {
                if ((bool)mo["IPEnabled"])
                {
                    if (ip != null && mask != null && gateway != null && dns != null)
                    {
                        ManagementBaseObject newIP = mo.GetMethodParameters("EnableStatic");
                        ManagementBaseObject newGateway = mo.GetMethodParameters("SetGateways");
                        ManagementBaseObject newDNS = mo.GetMethodParameters("SetDNSServerSearchOrder");
                        newIP["IPAddress"] = new string[] { ip };
                        newIP["SubnetMask"] = new string[] { mask };
                        newGateway["DefaultIPGateway"] = new string[] { gateway };
                        newDNS["DNSServerSearchOrder"] = new string[] { dns };
                        try
                        {
                            mo.InvokeMethod("EnableStatic", newIP, null);
                            mo.InvokeMethod("SetGateways", newGateway, null);
                            mo.InvokeMethod("SetDNSServerSearchOrder", newDNS, null);
                        }
                        catch { throw; }
                        break;
                    }
                    else
                    {
                        try
                        {
                            mo.InvokeMethod("SetDNSServerSearchOrder", null);
                            mo.InvokeMethod("EnableDHCP", null);
                        }
                        catch { throw; }
                        break;
                    }
                }
            }
        }

        public static void SetIP(IPSet ipSet, string dns)
        {
            if (ipSet == null || dns == "") throw new ArgumentNullException("ipSet/dns");
            SetIP(ipSet.DefaultIP, ipSet.Mask, ipSet.Gateway, dns);
        }
    }
}
