# Nmap.NET

Nmap.NET is an [nmap](http://www.nmap.org) wrapper library for .NET 7 which
aims to provide a simple interface for host discovery, firewall detection, and
port scanning.

## Usage & Examples

Using the library is fairly simple. A demo project is included in `Nmap.NET.Demo`, and some examples are provided below.

### Host discovery

Host discovery will yield a collection of `Host` objects, each containing information about the discovered host.

```C#
    using Nmap.NET;
    using Nmap.NET.Container;

    class Program
    {
        public static void Main(string[] args)
        {
            var target = new Target("192.168.0.0/24");
            var result = new Scanner(target).HostDiscovery();
            // do something with the result
        }
    }
```

### Port scan (TCP SYN scan)

```C#
    using Nmap.NET;
    using Nmap.NET.Container;

    class Program
    {
        public static void Main(string[] args)
        {
            var target = new Target("192.168.1.101");
            var result = new Scanner(target).PortScan(ScanType.Syn);
            // do something with the result
        }
    }
```

### A more advanced scan

```C#
    using Nmap.NET;
    using Nmap.NET.Container;

    class Program
    {
        public static void Main(string[] args)
        {
            // target can be a string, an IPAddress or an IEnumerable of either
            var target = new Target("192.168.1.0/24");
            var scanner = new Scanner(target);

            // multiple calls to scanner will always exclude this host
            scanner.PersistentOptions = new NmapOptions {
                {NmapFlag.ExcludeHosts, "192.168.0.12"}
            };
            var result = scanner.HostDiscovery();
            // do something with the result
        }
    }
```