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
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Asn1;
using System.Linq;
using Org.BouncyCastle.X509;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;
using Org.BouncyCastle.Utilities.Encoders;

namespace UnitTest
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void KeyGenTest()
        {
            TimeIt("SigneTbs", () =>
            {
                AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateRsaKeyPair(1024);
                String name = "rafik";
                String organization = "ANP";
                String organizationalUnit = "ESDAT";
                String city = "Réghaïa";
                String stateCode = "35";
                String countryCode = "DZ";
                String SubjectDN = $"CN={name},O={organization},OU={organizationalUnit},L={city},C={countryCode},ST={stateCode}";
                string algorithm = "SHA512WITHRSA";
                String[] subjectAlternativeNames = new List<String>().ToArray();

                int[] usage = { 128, 64, 32, 16, 8, 4, 2, 1, 32768 };
                int us = 0;
                for (int i = 0; i < 9; i++) us = us | usage[i];
                KeyUsage keyUsage = new KeyUsage(us);
                KeyPurposeID[] ExtendUsage = new List<KeyPurposeID>() { KeyPurposeID.AnyExtendedKeyUsage, KeyPurposeID.IdKPServerAuth ,KeyPurposeID.IdKPClientAuth,
                                                                    KeyPurposeID.IdKPCodeSigning,KeyPurposeID.IdKPEmailProtection,KeyPurposeID.IdKPIpsecEndSystem,
                                                                    KeyPurposeID.IdKPIpsecTunnel,KeyPurposeID.IdKPIpsecUser,KeyPurposeID.IdKPTimeStamping,
                                                                    KeyPurposeID.IdKPOcspSigning,KeyPurposeID.IdKPSmartCardLogon,KeyPurposeID.IdKPMacAddress}.ToArray();

                Pkcs10CertificationRequest pkcs10 = CertRequest(new X509Name(SubjectDN), subjectAlternativeNames, asymmetricCipherKeyPair, algorithm, keyUsage, ExtendUsage, false);
                RsaKeyParameters pubkey =(RsaKeyParameters)PublicKeyFactory.CreateKey(pkcs10.GetCertificationRequestInfo().SubjectPublicKeyInfo);
                Console.WriteLine("RSA Key size="+pubkey.Modulus.BitLength);
                Console.WriteLine("Signatur algo=" + SignerUtilities.GetEncodingName(pkcs10.SignatureAlgorithm.Algorithm));
                //*********************************************************************************************************************
                String name1 = "RoortCA";
                String organization1 = "ANP";
                String organizationalUnit1 = "ESDAT";
                String city1 = "alger";
                String countryCode1 = "DZ";
                String SubjectDN1 = $"CN={name1},O={organization1},OU={organizationalUnit1},L={city1},C={countryCode1}";
                AsymmetricCipherKeyPair asymmetricCipherKeyPair1 = GenerateEcKeyPair("sect571r1");
                
                string algorithm1 = "SHA512WITHECDSA";
               
                SecureRandom random = new SecureRandom();
                BigInteger SerialNumber = GenerateSerialNumber(random);
                X509Certificate Root = RootCA(SerialNumber, asymmetricCipherKeyPair1, SubjectDN1, subjectAlternativeNames, keyUsage, ExtendUsage, algorithm1, 20);
                
                //*********************************************************************************************************************
                BigInteger SerialNumber1 = GenerateSerialNumber(random);
               // AlgorithmIdentifier algorithm2 = new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha512);
                
               TbsCertificateStructure tbs = TbsCertificate(pkcs10, 5, SerialNumber1, Root);
                //*********************************************************************************************************************
               X509Certificate certificate = SigneTbs(tbs, Root, asymmetricCipherKeyPair1.Private);
               X509Certificate2 Certificate2 = new X509Certificate2(certificate.GetEncoded());
               Console.WriteLine(Certificate2.ToString(true));
               Console.WriteLine("*********************************************************************************************************************");
                //  ECPublicKeyParameters publicKeyParam = (ECPublicKeyParameters)asymmetricCipherKeyPair1.Public;
                // Console.WriteLine(publicKeyParam.Parameters.Curve.FieldSize);
                string pass = GeneratePassword(32);
                Console.WriteLine("pass is:" + pass );
                byte[] message = Encoding.ASCII.GetBytes(pass);
               
                Console.WriteLine(Hex.ToHexString(DigestUtilities.CalculateDigest("SHA3-512", message)));
                Console.WriteLine();
            });

            //TimeIt("GenerateDsaKeyPair", () =>
            //{
            //    AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateDsaKeyPair(512);

            //});

            //TimeIt("GenerateRsaKeyPair", () =>
            //{
            //    AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateRsaKeyPair(2048);
            //    String name = "rafik";
            //    String organization = "ANP";
            //    String organizationalUnit = "ESDAT";
            //    String city = "Réghaïa";
            //    String stateCode = "35";
            //    String countryCode = "DZ";
            //    String SubjectDN = $"CN={name},O={organization},OU={organizationalUnit},L={city},C={countryCode},ST={stateCode}";
            //    string algorithm = "SHA512WITHRSA";
            //    String[] subjectAlternativeNames = new List<String>().ToArray();
                
            //    int[] usage = { 128, 64, 32, 16, 8, 4, 2, 1, 32768 };
            //    int us = 0;
            //    for (int i = 0; i < 9; i++) us = us | usage[i];
            //    KeyUsage keyUsage = new KeyUsage(us);
            //    KeyPurposeID[] ExtendUsage = new List<KeyPurposeID>() { KeyPurposeID.AnyExtendedKeyUsage, KeyPurposeID.IdKPServerAuth ,KeyPurposeID.IdKPClientAuth,
            //                                                        KeyPurposeID.IdKPCodeSigning,KeyPurposeID.IdKPEmailProtection,KeyPurposeID.IdKPIpsecEndSystem,
            //                                                        KeyPurposeID.IdKPIpsecTunnel,KeyPurposeID.IdKPIpsecUser,KeyPurposeID.IdKPTimeStamping,
            //                                                        KeyPurposeID.IdKPOcspSigning,KeyPurposeID.IdKPSmartCardLogon,KeyPurposeID.IdKPMacAddress}.ToArray();

            //    Pkcs10CertificationRequest pkcs10 = CertRequest(new X509Name(SubjectDN), subjectAlternativeNames, asymmetricCipherKeyPair, algorithm, keyUsage, ExtendUsage,false);
                
            //    Console.WriteLine(ShowExtensions(pkcs10));
               
               

            //});
            
            //TimeIt("GenerateEcKeyPair", () =>
            //{
            //    AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateEcKeyPair("sect571r1");
            //    string Private = KeyWriter(asymmetricCipherKeyPair.Private);
            //    Console.WriteLine(Private);
            //    Console.WriteLine("********************************");
            //    AsymmetricKeyParameter P = PrivateKeyReader(Private);
            //    Console.WriteLine(KeyWriter(P));
            //    Console.WriteLine("********************************");
            //    string Public = KeyWriter(asymmetricCipherKeyPair.Public);
            //    Console.WriteLine(Public);
            //    Console.WriteLine("********************************");
            //    AsymmetricKeyParameter B = PublicKeyReader(Public);
            //    Console.WriteLine(KeyWriter(B));
            //});

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
            KeyPurposeID[] ExtendUsage = new List<KeyPurposeID>() { KeyPurposeID.AnyExtendedKeyUsage, KeyPurposeID.IdKPServerAuth ,KeyPurposeID.IdKPClientAuth,
                                                                    KeyPurposeID.IdKPCodeSigning,KeyPurposeID.IdKPEmailProtection,KeyPurposeID.IdKPIpsecEndSystem,
                                                                    KeyPurposeID.IdKPIpsecTunnel,KeyPurposeID.IdKPIpsecUser,KeyPurposeID.IdKPTimeStamping,
                                                                    KeyPurposeID.IdKPOcspSigning,KeyPurposeID.IdKPSmartCardLogon,KeyPurposeID.IdKPMacAddress}.ToArray();
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
                ECKeyParameters keyParameters = (ECKeyParameters)PublicKeyFactory.CreateKey(tbsCertificateStructure.SubjectPublicKeyInfo);
                Console.WriteLine("EC Key Size=" + keyParameters.Parameters.Curve.FieldSize);
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
