using System.Linq;
using System.Net.Sockets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Nmap.NET.Container;
using Simple.DotNMap;

namespace Nmap.NET.Test
{
    [TestClass]
    public class ScanResultUnitTests
    {
        [TestMethod]
        public void whenScanResultConstructedWithEmptyNmaprunThenHostsShouldBeEmpty()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.IsFalse(sr.Hosts.Any());
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenTotalShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "5643",
                                    down = "0",
                                    up = "0"
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(5643, sr.Total);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenDownShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "5643",
                                    up = "0"
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(5643, sr.Down);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenUpShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "5643"
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(5643, sr.Up);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenAddressShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new hostnames
                                                {
                                                    hostname = new[]
                                                        {
                                                            new hostname()
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("127.0.0.1", sr.Hosts.First().Address.ToString());
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenHostnameShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new hostnames
                                                {
                                                    hostname = new[]
                                                        {
                                                            new hostname
                                                                {
                                                                    name = "example.com"
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("example.com", sr.Hosts.First().Hostnames.First());
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenExtraPortsCountShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    extraports = new[]
                                                        {
                                                            new extraports
                                                                {
                                                                    count = "5643",
                                                                    state = string.Empty
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(5643, sr.Hosts.First().ExtraPorts.First().Count);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunAndNoExtraportsThenExtraPortsShouldBeEmpty()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[] {}
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.IsFalse(sr.Hosts.First().ExtraPorts.Any());
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenExtraPortsStateShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    extraports = new[]
                                                        {
                                                            new extraports
                                                                {
                                                                    count = "5643",
                                                                    state = "parsed"
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("parsed", sr.Hosts.First().ExtraPorts.First().State);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenPortPortNumberShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.tcp,
                                                                    state = new state
                                                                        {
                                                                            state1 = "parsed"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(5643, sr.Hosts.First().Ports.First().PortNumber);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunWithTcpAsProtocolThenPortProtocolShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.tcp,
                                                                    state = new state
                                                                        {
                                                                            state1 = "parsed"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(ProtocolType.Tcp, sr.Hosts.First().Ports.First().Protocol);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunWithUdpAsProtocolThenPortProtocolShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.udp,
                                                                    state = new state
                                                                        {
                                                                            state1 = "parsed"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(ProtocolType.Udp, sr.Hosts.First().Ports.First().Protocol);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunWithSctpAsProtocolThenPortProtocolShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.sctp,
                                                                    state = new state
                                                                        {
                                                                            state1 = "parsed"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            // SCTP isn't supported by Windows by default, so Unknown seems the most appropriate protocol to return
            Assert.AreEqual(ProtocolType.Unknown, sr.Hosts.First().Ports.First().Protocol);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunWithIpAsProtocolThenPortProtocolShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.ip,
                                                                    state = new state
                                                                        {
                                                                            state1 = "parsed"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(ProtocolType.IP, sr.Hosts.First().Ports.First().Protocol);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunAndPortIsFilteredThenPortFilteredShouldBeTrue()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.ip,
                                                                    state = new state
                                                                        {
                                                                            state1 = "filtered"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.IsTrue(sr.Hosts.First().Ports.First().Filtered);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunAndPortIsNotFilteredThenPortFilteredShouldBeFalse
            ()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.ip,
                                                                    state = new state
                                                                        {
                                                                            state1 = "notfiltered"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.IsFalse(sr.Hosts.First().Ports.First().Filtered);
        }

        [TestMethod]
        public void
            whenScanResultConstructedWithNmaprunAndServiceIsNotPresentThenPortServiceShouldBeDefault()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.ip,
                                                                    state = new state
                                                                        {
                                                                            state1 = "herpderp"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(default, sr.Hosts.First().Ports.First().Service);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunAndServiceIsPresentThenServiceNameShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.ip,
                                                                    state = new state
                                                                        {
                                                                            state1 = "herpderp"
                                                                        },
                                                                    service = new service
                                                                        {
                                                                            name = "Foobar",
                                                                            product = "Bizbaz",
                                                                            ostype = "DragonFly BSD",
                                                                            version = "2.718281828"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("Foobar", sr.Hosts.First().Ports.First().Service.Name);
        }

        [TestMethod]
        public void
            whenScanResultConstructedWithNmaprunAndServiceIsPresentThenServiceProductShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.ip,
                                                                    state = new state
                                                                        {
                                                                            state1 = "herpderp"
                                                                        },
                                                                    service = new service
                                                                        {
                                                                            name = "Foobar",
                                                                            product = "Bizbaz",
                                                                            ostype = "DragonFly BSD",
                                                                            version = "2.718281828"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("Bizbaz", sr.Hosts.First().Ports.First().Service.Product);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunAndServiceIsPresentThenServiceOsShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.ip,
                                                                    state = new state
                                                                        {
                                                                            state1 = "herpderp"
                                                                        },
                                                                    service = new service
                                                                        {
                                                                            name = "Foobar",
                                                                            product = "Bizbaz",
                                                                            ostype = "DragonFly BSD",
                                                                            version = "2.718281828"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("DragonFly BSD", sr.Hosts.First().Ports.First().Service.Os);
        }

        [TestMethod]
        public void
            whenScanResultConstructedWithNmaprunAndServiceIsPresentThenServiceVersionShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new ports
                                                {
                                                    port = new[]
                                                        {
                                                            new port
                                                                {
                                                                    portid = "5643",
                                                                    protocol = portProtocol.ip,
                                                                    state = new state
                                                                        {
                                                                            state1 = "herpderp"
                                                                        },
                                                                    service = new service
                                                                        {
                                                                            name = "Foobar",
                                                                            product = "Bizbaz",
                                                                            ostype = "DragonFly BSD",
                                                                            version = "2.718281828"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("2.718281828", sr.Hosts.First().Ports.First().Service.Version);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunAndNoPortsThenPortsShouldBeEmpty()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[] {}
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.IsFalse(sr.Hosts.First().Ports.Any());
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunAndNoHostnamesThenHostnamesShouldBeEmpty()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[] {}
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.IsFalse(sr.Hosts.First().Hostnames.Any());
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunAndNoOsmatchesThenOsMatchesShouldBeEmpty()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[] {}
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.IsFalse(sr.Hosts.First().OsMatches.Any());
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenOsMatchesCertaintyShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new os
                                                {
                                                    osmatch = new[]
                                                        {
                                                            new osmatch
                                                                {
                                                                    accuracy = "100",
                                                                    name = "Temple OS (www.templeos.org)",
                                                                    osclass = new[]
                                                                        {
                                                                            new osclass
                                                                                {
                                                                                    accuracy = "100",
                                                                                    osfamily = "Temple",
                                                                                    osgen = "apocalypse",
                                                                                    vendor = "Terry A. Davis"
                                                                                }
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual(100, sr.Hosts.First().OsMatches.First().Certainty);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenOsMatchesNameShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new os
                                                {
                                                    osmatch = new[]
                                                        {
                                                            new osmatch
                                                                {
                                                                    accuracy = "100",
                                                                    name = "Temple OS (www.templeos.org)",
                                                                    osclass = new[]
                                                                        {
                                                                            new osclass
                                                                                {
                                                                                    accuracy = "100",
                                                                                    osfamily = "Temple",
                                                                                    osgen = "apocalypse",
                                                                                    vendor = "Terry A. Davis"
                                                                                }
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("Temple OS (www.templeos.org)", sr.Hosts.First().OsMatches.First().Name);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenOsMatchesFamilyShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new os
                                                {
                                                    osmatch = new[]
                                                        {
                                                            new osmatch
                                                                {
                                                                    accuracy = "100",
                                                                    name = "Temple OS (www.templeos.org)",
                                                                    osclass = new[]
                                                                        {
                                                                            new osclass
                                                                                {
                                                                                    accuracy = "100",
                                                                                    osfamily = "Temple",
                                                                                    osgen = "apocalypse",
                                                                                    vendor = "Terry A. Davis"
                                                                                }
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("Temple", sr.Hosts.First().OsMatches.First().Family);
        }

        [TestMethod]
        public void whenScanResultConstructedWithNmaprunThenOsMatchesShouldBeCorrect()
        {
            var nr = new nmaprun
                {
                    runstats = new runstats
                        {
                            hosts = new hosts
                                {
                                    total = "0",
                                    down = "0",
                                    up = "0"
                                }
                        },
                    Items = new object[]
                        {
                            new host
                                {
                                    address = new address
                                        {
                                            addr = "127.0.0.1"
                                        },
                                    Items = new object[]
                                        {
                                            new os
                                                {
                                                    osmatch = new[]
                                                        {
                                                            new osmatch
                                                                {
                                                                    accuracy = "100",
                                                                    name = "Temple OS (www.templeos.org)",
                                                                    osclass = new[]
                                                                        {
                                                                            new osclass
                                                                                {
                                                                                    accuracy = "100",
                                                                                    osfamily = "Temple",
                                                                                    osgen = "apocalypse",
                                                                                    vendor = "Terry A. Davis"
                                                                                }
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                };
            var sr = new ScanResult(nr);

            Assert.AreEqual("apocalypse", sr.Hosts.First().OsMatches.First().Generation);
        }
    }
}