using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.NetworkInformation;

namespace Uninstall
{
    internal class Program
    {
        private static void Main()
        {
            try
            {
                ClearLocalNetworkInterfaces();
            }
            finally
            {
                Environment.Exit(0);
            }
        }

        /// <summary>
        ///		Execute process with arguments
        /// </summary>
        internal static void ExecuteWithArguments(string filename, string arguments)
        {
            try
            {
                const int timeout = 9000;
                using (var process = new Process())
                {
                    process.StartInfo.FileName = filename;
                    process.StartInfo.Arguments = arguments;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    process.Start();
                    if (process.WaitForExit(timeout))
                    {
                        if (process.ExitCode == 0)
                        {
                            //do nothing
                        }
                    }
                    else
                    {
                        // Timed out.
                        throw new Exception("Timed out");
                    }
                }
            }
            catch (Exception) { }
        }

        /// <summary>
        ///		 Clear all network interfaces.
        /// </summary>
        internal static void ClearLocalNetworkInterfaces()
        {
            try
            {
                string[] networkInterfaceBlacklist =
                {
                    "Microsoft Virtual",
                    "Hamachi Network",
                    "VMware Virtual",
                    "VirtualBox",
                    "Software Loopback",
                    "Microsoft ISATAP",
                    "Microsoft-ISATAP",
                    "Teredo Tunneling Pseudo-Interface",
                    "Microsoft Wi-Fi Direct Virtual",
                    "Microsoft Teredo Tunneling Adapter",
                    "Von Microsoft gehosteter",
                    "Microsoft hosted",
                    "Virtueller Microsoft-Adapter",
                    "TAP"
                };

                var networkInterfaces = new List<NetworkInterface>();
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                    {
                        continue;
                    }
                    foreach (var blacklistEntry in networkInterfaceBlacklist)
                    {
                        if (nic.Description.Contains(blacklistEntry) || nic.Name.Contains(blacklistEntry)) continue;
                        if (!networkInterfaces.Contains(nic))
                        {
                            networkInterfaces.Add(nic);
                        }
                    }
                }

                foreach (var networkInterface in networkInterfaces)
                {
                    ExecuteWithArguments("netsh", $"interface ipv4 delete dns \"{networkInterface.Name}\" all");
                    ExecuteWithArguments("netsh", $"interface ipv6 delete dns \"{networkInterface.Name}\" all");
                }
            }
            catch (Exception)
            {
            }
        }
    }
}
