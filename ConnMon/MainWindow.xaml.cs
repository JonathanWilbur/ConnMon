using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

public enum TCP_TABLE_CLASS : int
{
    TCP_TABLE_BASIC_LISTENER,
    TCP_TABLE_BASIC_CONNECTIONS,
    TCP_TABLE_BASIC_ALL,
    TCP_TABLE_OWNER_PID_LISTENER,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
    TCP_TABLE_OWNER_PID_ALL,
    TCP_TABLE_OWNER_MODULE_LISTENER,
    TCP_TABLE_OWNER_MODULE_CONNECTIONS,
    TCP_TABLE_OWNER_MODULE_ALL
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCPROW_OWNER_PID
{
    public uint state;
    public uint localAddr;
    public byte localPort1;
    public byte localPort2;
    public byte localPort3;
    public byte localPort4;
    public uint remoteAddr;
    public byte remotePort1;
    public byte remotePort2;
    public byte remotePort3;
    public byte remotePort4;
    public int owningPid;

    public ushort LocalPort
    {
        get
        {
            return BitConverter.ToUInt16(
                new byte[2] { localPort2, localPort1 }, 0);
        }
    }

    public ushort RemotePort
    {
        get
        {
            return BitConverter.ToUInt16(
                new byte[2] { remotePort2, remotePort1 }, 0);
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCPTABLE_OWNER_PID
{
    public uint dwNumEntries;
    MIB_TCPROW_OWNER_PID table;
}

public class Row
{
    private string processName;
    private int processId;
    private string remoteAddress;
    private ushort remotePort;

    public string ProcessName { get => processName; set => processName = value; }
    public int ProcessId { get => processId; set => processId = value; }
    public string RemoteAddress { get => remoteAddress; set => remoteAddress = value; }
    public ushort RemotePort { get => remotePort; set => remotePort = value; }
}


namespace ConnMon
{
    public class NetworkInfo
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int dwOutBufLen,
            bool sort,
            int ipVersion,
            TCP_TABLE_CLASS tblClass,
            int reserved
        );

        public static MIB_TCPROW_OWNER_PID[] GetAllTcpConnections()
        {
            MIB_TCPROW_OWNER_PID[] tTable;
            int AF_INET = 2;    // IP_v4
            int buffSize = 0;

            // how much memory do we need?
            uint ret = GetExtendedTcpTable(IntPtr.Zero,
                ref buffSize,
                true,
                AF_INET,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL,
                0);
            if (ret != 0 && ret != 122) // 122 insufficient buffer size
                throw new Exception("bad ret on check " + ret);
            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);

            try
            {
                ret = GetExtendedTcpTable(buffTable,
                    ref buffSize,
                    true,
                    AF_INET,
                    TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (ret != 0)
                    throw new Exception("bad ret " + ret);

                // get the number of entries in the table
                MIB_TCPTABLE_OWNER_PID tab =
                    (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(
                        buffTable,
                        typeof(MIB_TCPTABLE_OWNER_PID));
                IntPtr rowPtr = (IntPtr)((long)buffTable +
                    Marshal.SizeOf(tab.dwNumEntries));
                tTable = new MIB_TCPROW_OWNER_PID[tab.dwNumEntries];

                for (int i = 0; i < tab.dwNumEntries; i++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal
                        .PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    tTable[i] = tcpRow;
                    // next entry
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(tcpRow));
                }
            }
            finally
            {
                // Free the Memory
                Marshal.FreeHGlobal(buffTable);
            }
            return tTable;
        }

        public static string IpUintToString(uint ipUint)
        {
            var ipBytes = BitConverter.GetBytes(ipUint);
            var ipBytesRevert = new byte[4];
            ipBytesRevert[0] = ipBytes[0];
            ipBytesRevert[1] = ipBytes[1];
            ipBytesRevert[2] = ipBytes[2];
            ipBytesRevert[3] = ipBytes[3];
            return new IPAddress(ipBytesRevert).ToString();
        }
    }

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public void Render(object sender, EventArgs e)
        {
            Brush gridDataFontColor = Brushes.White;
            Grid grid = new Grid();
            ColumnDefinition processNameColumn = new ColumnDefinition();
            ColumnDefinition processIDColumn = new ColumnDefinition();
            ColumnDefinition remoteAddressColumn = new ColumnDefinition();
            ColumnDefinition remotePortColumn = new ColumnDefinition();

            grid.ColumnDefinitions.Add(processNameColumn);
            grid.ColumnDefinitions.Add(processIDColumn);
            grid.ColumnDefinitions.Add(remoteAddressColumn);
            grid.ColumnDefinitions.Add(remotePortColumn);

            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            TcpConnectionInformation[] connections = properties.GetActiveTcpConnections();
            var conns = NetworkInfo.GetAllTcpConnections();

            for (int i = 0; i < conns.Length; i++)
            {
                var conn = conns[i];
                TextBlock processNameText = new TextBlock();
                try
                {
                    processNameText.Text = Process.GetProcessById(conn.owningPid).MainModule.FileName;
                }
                catch (ArgumentNullException)
                {
                    processNameText.Text = "ARGNEX";
                    continue;
                }
                catch (ArgumentException)
                {
                    processNameText.Text = "ARGEX";
                    continue;
                }
                catch (InvalidOperationException)
                {
                    processNameText.Text = "INVOPEX";
                    continue;
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    processNameText.Text = "CANNOT";
                    continue;
                }
                processNameText.Style = (Style)Resources["GridText"];
                Grid.SetRow(processNameText, i);
                Grid.SetColumn(processNameText, 0);

                TextBlock processIdText = new TextBlock();
                processIdText.Text = conn.owningPid.ToString();
                processIdText.Style = (Style)Resources["GridText"];
                Grid.SetRow(processIdText, i);
                Grid.SetColumn(processIdText, 1);

                TextBlock remoteAddressText = new TextBlock();
                remoteAddressText.Text = NetworkInfo.IpUintToString(conn.remoteAddr);
                remoteAddressText.Style = (Style)Resources["GridText"];
                Grid.SetRow(remoteAddressText, i);
                Grid.SetColumn(remoteAddressText, 2);

                TextBlock remotePortText = new TextBlock();
                remotePortText.Text = conn.RemotePort.ToString();
                remotePortText.Style = (Style)Resources["GridText"];
                Grid.SetRow(remotePortText, i);
                Grid.SetColumn(remotePortText, 3);

                RowDefinition rowDef = new RowDefinition();
                rowDef.Height = new GridLength(20);
                grid.RowDefinitions.Add(rowDef);

                grid.Children.Add(processIdText);
                grid.Children.Add(processNameText);
                grid.Children.Add(remoteAddressText);
                grid.Children.Add(remotePortText);
            }
            this.Content = grid;
        }

        public void RenderLoop ()
        {
            var dispatchTimer = new System.Windows.Threading.DispatcherTimer();
            dispatchTimer.Tick += new EventHandler(this.Render);
            dispatchTimer.Interval = new TimeSpan(0, 0, 1);
            dispatchTimer.Start();
        }
        
        public MainWindow()
        {
            InitializeComponent();
            this.Left = System.Windows.SystemParameters.PrimaryScreenWidth - 1200;
            this.Top = 10;
            this.Height = System.Windows.SystemParameters.PrimaryScreenHeight - 100;
            this.RenderLoop();
        }
    }
}
