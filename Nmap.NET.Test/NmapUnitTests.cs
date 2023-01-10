using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Nmap.NET.Test
{
    [TestClass]
    public class NmapOptionsUnitTests
    {
        [TestMethod]
        public void whenOptionIsAddedThenKeysContainsFlag()
        {
            var no = new NmapOptions
            {
                { NmapFlag.A, string.Empty }
            };

            Assert.IsTrue(no.ContainsKey(NmapFlag.A));
        }

        [TestMethod]
        public void whenOptionIsAddedThenValuesContainsArguments()
        {
            var no = new NmapOptions
            {
                { NmapFlag.A, "All they have is bow-dow-bow-dow-bow-dow-do-dee-do-dow-dee-do" }
            };
            Assert.IsTrue(no.Values.Contains("All they have is bow-dow-bow-dow-bow-dow-do-dee-do-dow-dee-do"));
        }

        [TestMethod]
        public void whenOptionIsAddedThenKeyRetrievesArguments()
        {
            var no = new NmapOptions
            {
                { NmapFlag.A, "Heartbreak under the streetlights" }
            };
            Assert.AreEqual("Heartbreak under the streetlights", no[NmapFlag.A]);
        }

        [TestMethod]
        public void whenExistingOptionIsAddedThenArgumentsAreCommaSeparated()
        {
            var no = new NmapOptions
            {
                { NmapFlag.A, "A" },
                { NmapFlag.A, "B" }
            };
            Assert.AreEqual("A,B", no[NmapFlag.A]);
        }

        [TestMethod]
        public void whenToStringIsCalledWithOneOptionSpecifiedThenOutputIsFormattedCorrectly()
        {
            var no = new NmapOptions
            {
                { NmapFlag.A, "A" }
            };
            Assert.AreEqual("-A A", no.ToString());
        }

        [TestMethod]
        public void whenToStringIsCalledWithMultipleOptionsSpecifiedThenOutputIsFormattedCorrectly()
        {
            var no = new NmapOptions
            {
                { NmapFlag.A, "A" },
                { NmapFlag.SourcePortG, "B" }
            };

            Assert.AreEqual("-A A -g B", no.ToString());
        }
    }

    [TestClass]
    public class NmapContextUnitTests
    {
        [TestMethod]
        [ExpectedException(typeof (ApplicationException))]
        public void whenRunIsCalledAndOutputPathIsEmptyThenShouldThrowApplicationException()
        {
            var nc = new NmapContext
                {
                    OutputPath = string.Empty
                };
            nc.Run();
        }

        [TestMethod]
        [ExpectedException(typeof (ApplicationException))]
        public void whenRunIsCalledAndOutputPathIsNullThenShouldThrowApplicationException()
        {
            var nc = new NmapContext
                {
                    OutputPath = null
                };
            nc.Run();
        }

        [TestMethod]
        [ExpectedException(typeof (ApplicationException))]
        public void whenRunIsCalledAndPathIsEmptyThenShouldThrowApplicationException()
        {
            var nc = new NmapContext
                {
                    Path = string.Empty
                };
            nc.Run();
        }

        [TestMethod]
        [ExpectedException(typeof (ApplicationException))]
        public void whenRunIsCalledAndPathIsNullThenShouldThrowApplicationException()
        {
            var nc = new NmapContext
                {
                    Path = null
                };
            nc.Run();
        }

        [TestMethod]
        [ExpectedException(typeof (ApplicationException))]
        public void whenRunIsCalledAndPathIsInvalidThenShouldThrowApplicationException()
        {
            var nc = new NmapContext
                {
                    Path = Path.GetRandomFileName()
                };
            nc.Run();
        }

        [TestMethod]
        [ExpectedException(typeof (ApplicationException))]
        public void whenRunIsCalledAndTargetIsEmptyThenShouldThrowApplicationException()
        {
            var nc = new NmapContext
                {
                    Target = string.Empty
                };
            nc.Run();
        }

        [TestMethod]
        [ExpectedException(typeof (ApplicationException))]
        public void whenRunIsCalledAndOptionsIsNullThenShouldThrowApplicationException()
        {
            var nc = new NmapContext
                {
                    Options = null
                };
            nc.Run();
        }
    }
}