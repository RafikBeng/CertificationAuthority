using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto;
using System;
using System.Diagnostics;
using static Certlib.KeyGen;
namespace UnitTest
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void KeyGenTest()
        {
            TimeIt("GenerateElGamalKeyPair", () =>
            {
              AsymmetricCipherKeyPair asymmetricCipherKeyPair= GenerateElGamalKeyPair(512);

            });

            TimeIt("GenerateDsaKeyPair", () =>
            {
                AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateDsaKeyPair(1024);

            });

            TimeIt("GenerateRsaKeyPair", () =>
            {
                AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateRsaKeyPair(2048);

            });

            TimeIt("GenerateEcKeyPair", () =>
            {
                AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateEcKeyPair("sect571r1");
            });

            Debugger.Break();
        }
        private void TimeIt(String title, Action code)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            code();

            stopwatch.Stop();

            Debug.WriteLine($"{title} - {stopwatch.Elapsed.ToString()}");
        }
    }
}
