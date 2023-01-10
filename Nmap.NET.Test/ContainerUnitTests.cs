using System.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Nmap.NET.Container;

namespace Nmap.NET.Test
{
    [TestClass]
    public class TargetUnitTests
    {
        [TestMethod]
        public void whenTargetConstructedWithStringsThenToStringShouldYieldSpaceSeparatedTarget()
        {
            var t = new Target(new[] {"this", "is", "a", "test"});
            Assert.AreEqual("this is a test", t.ToString());
        }

        [TestMethod]
        public void whenTargetConstructedWithStringThenToStringShouldYieldTarget()
        {
            var t = new Target("this is a test");
            Assert.AreEqual("this is a test", t.ToString());
        }

        [TestMethod]
        public void whenTargetConstructedWithIPAddressThenToStringShouldYieldTarget()
        {
            var t = new Target(IPAddress.Parse("127.0.0.1"));
            Assert.AreEqual("127.0.0.1", t.ToString());
        }

        [TestMethod]
        public void whenTargetConstructedWithIPAddressesThenToStringShouldYieldSpaceSeparatedTarget()
        {
            var t =
                new Target(new[]
                    {IPAddress.Parse("127.0.0.1"), IPAddress.Parse("127.0.0.2"), IPAddress.Parse("127.0.0.3")});
            Assert.AreEqual("127.0.0.1 127.0.0.2 127.0.0.3", t.ToString());
        }
    }
}