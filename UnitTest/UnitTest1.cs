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
using Microsoft.VisualBasic.CompilerServices;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.TeleTrust;

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
                AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateRsaKeyPair(2048);
                String name = "rafik";
                String organization = "ANP";
                String organizationalUnit = "ESDAT";
                String city = "Réghaïa";
                String stateCode = "35";
                String countryCode = "DZ";
                String SubjectDN = $"CN={name},O={organization},OU={organizationalUnit},L={city},C={countryCode},ST={stateCode}";
                string algorithm = "SHA-256WITHRSA";
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
                AsymmetricCipherKeyPair asymmetricCipherKeyPair1 = GenerateRsaKeyPair(1024);
                AsymmetricCipherKeyPair asymmetricCipherKeyPair3 = GenerateEcKeyPair("secp521r1");
                string algorithm1 = "SHA-512WITHRSA";
                string algorithm5 = "SHA3-384withECDSA";
               // string algorithm1 = "SHA3-512WITHECDSA";
                SecureRandom random = new SecureRandom();
                BigInteger SerialNumber = GenerateSerialNumber(random);
                X509Certificate Root = RootCA(SerialNumber, asymmetricCipherKeyPair, SubjectDN1, subjectAlternativeNames, keyUsage, ExtendUsage, algorithm1, 20);
                File.WriteAllText("d:/folder/Root.cer", CertWriter(Root));

                // Console.WriteLine(SignerUtilities.GetDefaultX509Parameters(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512));
               // AlgorithmIdentifier identifier = new AlgorithmIdentifier(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);
               // Console.WriteLine(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512.Id);
                //  Console.WriteLine(SignerUtilities.GetDefaultX509Parameters(PkcsObjectIdentifiers.Sha512WithRsaEncryption));
                //foreach (var item in Asn1SignatureFactory.SignatureAlgNames)
                //{
                //    Console.WriteLine(item.ToString());
                //}
                //*********************************************************************************************************************
                BigInteger SerialNumber1 = GenerateSerialNumber(random);
                BigInteger SerialNumber2 = GenerateSerialNumber(random);
                // AlgorithmIdentifier algorithm2 = new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha512);

               // TbsCertificateStructure tbs = TbsCertificate1(pkcs10, 5, SerialNumber1, Root);
                TbsCertificateStructure tbs1 = TbsCertificate(pkcs10, 5, SerialNumber2, Root);
                
              
                //*********************************************************************************************************************
                  X509Certificate certificate = SigneTbs(tbs1, Root, asymmetricCipherKeyPair1.Private);
               
                Console.WriteLine(certificate.GetSignature().Length);
                Console.WriteLine(certificate.CertificateStructure.GetSignatureOctets().Length);

                // Console.WriteLine("***********************************encoder end der encoded***************************************************************");
                //X509Certificate test = SigneTbs(tbs, Root, asymmetricCipherKeyPair1.Private);
                //X509Certificate test1 = SigneTbs1(tbs, Root, asymmetricCipherKeyPair1.Private);

                //Console.WriteLine(test.GetHashCode());
                //Console.WriteLine(test1.GetHashCode());
                
                File.WriteAllText("d:/folder/certificate.cer", CertWriter(certificate));
                // File.WriteAllText("d:/folder/test1.cer", CertWriter(test1));
                // Console.WriteLine(Encoding.Default.EncodingName);

                //String algo = Root.SigAlgName;
                //algo = algo.Remove(algo.IndexOf("-"), 1);

                //var signer = SignerUtilities.GetSigner(algo);

                //AlgorithmIdentifier algo1= new DefaultSignatureAlgorithmIdentifierFinder().Find(algo);
                //DefaultDigestAlgorithmIdentifierFinder finder = new DefaultDigestAlgorithmIdentifierFinder();
                //var digestname = finder.find(algo1);


                //byte[] tbsDigest = DigestUtilities.CalculateDigest(DigestUtilities.GetAlgorithmName(digestname.Algorithm), tbs.GetDerEncoded());


                //ISigner sig = SignerUtilities.GetSigner(algorithm1);
                //sig.Init(false, asymmetricCipherKeyPair1.Public);
                //byte[] b = test1.GetEncoded();
                //sig.BlockUpdate(b, 0, b.Length);
                //if (!sig.VerifySignature(test1.GetSignature()))
                //{
                //    Console.WriteLine("signature not mapped correctly.");
                //}
                //else
                //{
                //    Console.WriteLine("signature  mapped correctly.");
                //}

                //Console.WriteLine("***********************************encoder end der encoded***************************************************************");
                //// X509Certificate2 Certificate2 = new X509Certificate2(certificate.GetEncoded());
                //// Console.WriteLine(Certificate2.ToString(true));
                //Console.WriteLine("*********************************************************************************************************************");
                ////  ECPublicKeyParameters publicKeyParam = (ECPublicKeyParameters)asymmetricCipherKeyPair1.Public;
                //// Console.WriteLine(publicKeyParam.Parameters.Curve.FieldSize);
                //string pass = GeneratePassword(32);
                //Console.WriteLine("pass is:" + pass );
                //byte[] message = Encoding.ASCII.GetBytes(pass);

                //Console.WriteLine(Hex.ToHexString(DigestUtilities.CalculateDigest("SHA3-512", message)));
                //Console.WriteLine();
                //Console.WriteLine("*********************************************************************************************************************");
                //DateTime dateTime = DateTime.UtcNow;

                //DateTime dateTime1 = dateTime.AddYears(5);
                //Console.WriteLine(dateTime1);
                //Console.WriteLine(dateTime);
                //TimeSpan timeSpan = dateTime1 - dateTime;
                //Console.WriteLine(dateTime1 - dateTime);

                //Console.WriteLine(dateTime.Add(timeSpan));







                // X509Certificate cert = RenewCertificate(certificate,asymmetricCipherKeyPair1.Private);
                // Console.WriteLine(cert.SubjectDN.ToString());
                //foreach(var v in certificate.GetExtendedKeyUsage())
                // {
                //     Console.WriteLine(v);
                // }
                // AsymmetricCipherKeyPair keyPair = GetKey(Root);
                //X509V2CrlGenerator crlGenerator = new X509V2CrlGenerator();
                //crlGenerator.SetIssuerDN(Root.IssuerDN);
                //crlGenerator.SetThisUpdate(dateTime);
                //crlGenerator.SetNextUpdate(dateTime1);
                //crlGenerator.AddCrlEntry(certificate.SerialNumber, dateTime, CrlReason.KeyCompromise);
                //crlGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(Root));
                //crlGenerator.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.One));
                //ISignatureFactory signatureFactory = new Asn1SignatureFactory(algorithm1, asymmetricCipherKeyPair1.Private, random);
                //X509Crl crl = crlGenerator.Generate(signatureFactory);
                //Stream stream = File.Create("d:/test.crl");
                //BinaryWriter binaryWriter = new BinaryWriter(stream);

                //binaryWriter.Write(crl.GetEncoded());
                //binaryWriter.Flush();
                //binaryWriter.Close();

                //*******************************************************************************
                //X509V2CrlGenerator crlGenerator1 = new X509V2CrlGenerator();
                //crlGenerator1.SetIssuerDN(Root.IssuerDN);
                //crlGenerator1.SetThisUpdate(dateTime);
                //crlGenerator1.SetNextUpdate(dateTime1);
                //crlGenerator1.AddCrl(crl);
                //crlGenerator1.AddCrlEntry(certificate1.SerialNumber, dateTime, CrlReason.CessationOfOperation);
                //crlGenerator1.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(Root));
                //crlGenerator1.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.Ten));
                //X509Crl crl1 = crlGenerator1.Generate(signatureFactory);
                //Stream stream1 = File.Create("d:/test1.crl");
                //BinaryWriter binaryWriter1 = new BinaryWriter(stream1);
                //binaryWriter1.Write(crl1.GetEncoded());
                //binaryWriter1.Flush();
                //binaryWriter1.Close();
                //Asn1OctetString octetString = crl.GetExtensionValue(X509Extensions.CrlNumber);
                //Asn1OctetString octetString1 = crl1.GetExtensionValue(X509Extensions.CrlNumber);
                //long number = CrlNumber.GetInstance(X509ExtensionUtilities.FromExtensionValue(octetString1)).LongValueExact;



                //Int64 ser = Int64.Parse(BitConverter.ToString(octetString.GetOctets()));
                // Console.WriteLine(CrlWriter(crl1));
                // Console.WriteLine(number);
                //var revoked = crl1.GetRevokedCertificates();

                //foreach(var v in revoked)
                //{
                //    Console.WriteLine("type of revoked is" + v.GetType());
                //    //Asn1OctetString octetString2 = v.GetExtensionValue(X509Extensions.ReasonCode);
                //    //DerEnumerated derEnumerated = (DerEnumerated)X509ExtensionUtilities.FromExtensionValue(octetString2);
                //    //Console.WriteLine(derEnumerated.IntValueExact);
                //}
                //Pkcs8Generator pkcs8Generator = new Pkcs8Generator(asymmetricCipherKeyPair.Private, Pkcs8Generator.PbeSha1_RC2_128);
                //pkcs8Generator.Password = new char[] {'r', 'a', 'f', 'i', 'k' };
                //pkcs8Generator.SecureRandom = new SecureRandom();


                //PemObject pem = pkcs8Generator.Generate();
                //TextWriter textWriter = new StringWriter();
                //Org.BouncyCastle.OpenSsl.PemWriter writer = new Org.BouncyCastle.OpenSsl.PemWriter(textWriter);
                //writer.WriteObject(pem.Generate());

                //writer.Writer.Flush();
                //string str = textWriter.ToString();
                //Console.WriteLine(str);
                //Console.WriteLine(KeyWriter(asymmetricCipherKeyPair.Private));
                //Console.WriteLine(KeyWriter(asymmetricCipherKeyPair.Public));
                //var dtf =new DefaultSignatureAlgorithmIdentifierFinder();


                //X509Name name22 = certificate.SubjectDN;
                //var nameval = name22.GetValueList(X509Name.CN)[0];


                //Console.WriteLine(nameval);
                //Console.WriteLine(PbeUtilities.GetEncodingName(BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc));
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
             
               
                
            });
            //TimeIt("RSA Key Generation dot net openssl", () =>
            //{
            //    RSAOpenSsl rSAOpenSsl = new RSAOpenSsl(8192);


            //    Console.WriteLine(rSAOpenSsl.KeySize);

            //});
            //TimeIt("RSA Key Generation dot net RSA.Create", () =>
            //{
            //    RSA rSA = RSA.Create(8192*2);

            //    Console.WriteLine(rSA.ExportRSAPublicKey());

            //});
            //TimeIt("RSA Key Generation dot net", () =>
            //{
            //   // AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateRsaKeyPair(8192);
            //    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(8192*2);

            //   Console.WriteLine(rsa.ExportRSAPublicKey());

            //});
            //TimeIt("RSA Key Generation dot net CNG", () =>
            //{
            //    RSACng rSACng = new RSACng(8192*2);

            //    Console.WriteLine(rSACng.ExportRSAPublicKey());

            //});
            //TimeIt("RSA Key Generation BC", () =>
            //{
            //    AsymmetricCipherKeyPair asymmetricCipherKeyPair = GenerateRsaKeyPair(8192*2);
            //    //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048 * 8);

            //    //Console.WriteLine(rsa.KeySize);

            //});

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
