using System;
using System.Linq;
using Nmap.NET.Container;

namespace Nmap.NET.Demo
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Console.Write("Enter an IP or subnet: ");
            var target = new Target(Console.ReadLine().Trim());
            Console.WriteLine("Initializing scan of {0}", target);
            ScanResult result = new Scanner(target, System.Diagnostics.ProcessWindowStyle.Hidden).PortScan();
            Console.WriteLine("Detected {0} host(s), {1} up and {2} down.", result.Total, result.Up, result.Down);
            foreach (Host i in result.Hosts)
            {
                Console.WriteLine("Host: {0}", i.Address);
                foreach (Port j in i.Ports)
                {
                    Console.Write("\tport {0}", j.PortNumber);
                    if (!string.IsNullOrEmpty(j.Service.Name))
                    {
                        Console.Write(" is running {0}", j.Service.Name);
                    }

                    if (j.Filtered)
                    {
                        Console.Write(" is filtered");
                    }

                    Console.WriteLine();
                }

                if (i.OsMatches.Any())
                {
                    Console.WriteLine("and is probably running {0}", i.OsMatches.First().Name);
                }
            }

            Console.Read();
        }
    }
}