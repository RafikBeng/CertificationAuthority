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
using Org.BouncyCastle.Asn1.Nist;
using System.Security.Cryptography;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.Pkix;
using System.IO;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Bcpg;

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
                BigInteger SerialNumber2 = GenerateSerialNumber(random);
                // AlgorithmIdentifier algorithm2 = new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha512);

                TbsCertificateStructure tbs = TbsCertificate(pkcs10, 5, SerialNumber1, Root);
                TbsCertificateStructure tbs1 = TbsCertificate(pkcs10, 5, SerialNumber2, Root);
                //*********************************************************************************************************************
                X509Certificate certificate = SigneTbs(tbs, Root, asymmetricCipherKeyPair1.Private);
                X509Certificate certificate1 = SigneTbs(tbs1, Root, asymmetricCipherKeyPair1.Private);
                // X509Certificate2 Certificate2 = new X509Certificate2(certificate.GetEncoded());
                // Console.WriteLine(Certificate2.ToString(true));
                Console.WriteLine("*********************************************************************************************************************");
                //  ECPublicKeyParameters publicKeyParam = (ECPublicKeyParameters)asymmetricCipherKeyPair1.Public;
                // Console.WriteLine(publicKeyParam.Parameters.Curve.FieldSize);
                string pass = GeneratePassword(32);
                Console.WriteLine("pass is:" + pass );
                byte[] message = Encoding.ASCII.GetBytes(pass);
               
                Console.WriteLine(Hex.ToHexString(DigestUtilities.CalculateDigest("SHA3-512", message)));
                Console.WriteLine();
                Console.WriteLine("*********************************************************************************************************************");
                DateTime dateTime = DateTime.UtcNow;
                
                DateTime dateTime1 = dateTime.AddYears(5);
                Console.WriteLine(dateTime1);
                Console.WriteLine(dateTime);
                TimeSpan timeSpan = dateTime1 - dateTime;
                Console.WriteLine(dateTime1 - dateTime);
               
                Console.WriteLine(dateTime.Add(timeSpan));







                // X509Certificate cert = RenewCertificate(certificate,asymmetricCipherKeyPair1.Private);
                // Console.WriteLine(cert.SubjectDN.ToString());
                //foreach(var v in certificate.GetExtendedKeyUsage())
                // {
                //     Console.WriteLine(v);
                // }
                // AsymmetricCipherKeyPair keyPair = GetKey(Root);
                X509V2CrlGenerator crlGenerator = new X509V2CrlGenerator();
                crlGenerator.SetIssuerDN(Root.IssuerDN);
                crlGenerator.SetThisUpdate(dateTime);
                crlGenerator.SetNextUpdate(dateTime1);
                crlGenerator.AddCrlEntry(certificate.SerialNumber, dateTime, CrlReason.KeyCompromise);
                crlGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(Root));
                crlGenerator.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.One));
                ISignatureFactory signatureFactory = new Asn1SignatureFactory(algorithm1, asymmetricCipherKeyPair1.Private, random);
                X509Crl crl = crlGenerator.Generate(signatureFactory);
                Stream stream = File.Create("d:/test.crl");
                BinaryWriter binaryWriter = new BinaryWriter(stream);
                
                binaryWriter.Write(crl.GetEncoded());
                binaryWriter.Flush();
                binaryWriter.Close();

                //*******************************************************************************
                X509V2CrlGenerator crlGenerator1 = new X509V2CrlGenerator();
                crlGenerator1.SetIssuerDN(Root.IssuerDN);
                crlGenerator1.SetThisUpdate(dateTime);
                crlGenerator1.SetNextUpdate(dateTime1);
                crlGenerator1.AddCrl(crl);
                crlGenerator1.AddCrlEntry(certificate1.SerialNumber, dateTime, CrlReason.CessationOfOperation);
                crlGenerator1.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(Root));
                crlGenerator1.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.Ten));
                X509Crl crl1 = crlGenerator1.Generate(signatureFactory);
                Stream stream1 = File.Create("d:/test1.crl");
                BinaryWriter binaryWriter1 = new BinaryWriter(stream1);
                binaryWriter1.Write(crl1.GetEncoded());
                binaryWriter1.Flush();
                binaryWriter1.Close();
                Asn1OctetString octetString = crl.GetExtensionValue(X509Extensions.CrlNumber);
                Asn1OctetString octetString1 = crl1.GetExtensionValue(X509Extensions.CrlNumber);
                long number = CrlNumber.GetInstance(X509ExtensionUtilities.FromExtensionValue(octetString1)).LongValueExact;
                


                //Int64 ser = Int64.Parse(BitConverter.ToString(octetString.GetOctets()));
                Console.WriteLine(CrlWriter(crl1));
                Console.WriteLine(number);
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
