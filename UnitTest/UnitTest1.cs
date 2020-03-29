using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using static Certlib.KeyGen;
using static Certlib.CertGen;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X9;

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
                AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateDsaKeyPair(512);

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

        [TestMethod]
        public void TbsGenTest()
        {
            String name = "rafik";
            String issuer = "Root CA";
            String organization = "ANP";
            String organizationalUnit = "ESDAT";
            String city = "Réghaïa";
            String stateCode = "35";
            String countryCode = "DZ";
            String subjectDN = $"CN={name},O={organization},OU={organizationalUnit},L={city},C={countryCode},ST={stateCode}";
            String issuerDN = $"CN={issuer},O={organization},OU={organizationalUnit},L={city},C={countryCode},ST={stateCode}";
            String[] subjectAlternativeNames = new List<String>().ToArray();
            KeyPurposeID[] ExtendUsage = new List<KeyPurposeID>() { KeyPurposeID.AnyExtendedKeyUsage, KeyPurposeID.IdKPServerAuth ,KeyPurposeID.IdKPClientAuth,KeyPurposeID.IdKPCodeSigning,KeyPurposeID.IdKPEmailProtection,KeyPurposeID.IdKPIpsecEndSystem,KeyPurposeID.IdKPIpsecTunnel,KeyPurposeID.IdKPIpsecUser,KeyPurposeID.IdKPTimeStamping,KeyPurposeID.IdKPOcspSigning,KeyPurposeID.IdKPSmartCardLogon,KeyPurposeID.IdKPMacAddress
}.ToArray();
            int[] usage = { 128, 64, 32, 16, 8, 4, 2, 1, 32768 };
            int us = 0;
            for (int i = 0; i < 9; i++) us = us | usage[i];
            KeyUsage keyUsage = new KeyUsage(us);
            BigInteger SerialNumber= GenerateSerialNumber(new SecureRandom());
            AlgorithmIdentifier algorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha512);
            TimeIt("GenerateEcKeyPair", () =>
            {
                AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateEcKeyPair("sect571r1");
                TbsCertificateStructure tbsCertificateStructure = TbsCertificate(subjectDN, issuerDN, subjectAlternativeNames, asymmetricCipherKeyPair, SerialNumber, keyUsage, ExtendUsage, algorithm, 5, false);
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
