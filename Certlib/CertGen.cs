using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;
namespace Certlib
{
    public  class CertGen

    {
        public static X509Certificate2 ConvertCertificate(X509Certificate certificate,
                                                           AsymmetricCipherKeyPair subjectKeyPair,
                                                           SecureRandom random,String password)
        {

            var store = new Pkcs12Store();
            string friendlyName = certificate.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });
            
            var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), random);
            var convertedCertificate =
                new X509Certificate2(stream.ToArray(),
                                     password,
                                     System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet | System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
            return convertedCertificate;
        }

        public static void ExportCertificateAsPfx(X509Certificate2 certificate, String outputFileName, String password = null)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));
            if (String.IsNullOrWhiteSpace(outputFileName))
                throw new ArgumentException($"Argument \"{nameof(outputFileName)}\" cannot be null or empty.", nameof(outputFileName));
            
            Byte[] bytes = certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, password);

            File.WriteAllBytes(outputFileName, bytes);
        }
        public static string GetReasonCode(int Reason)
        {
            return Reason switch
            {
                0 => ("unspecified"),
                1 => ("key Compromise"),
                3 => ("Affiliation Changed"),
                4 => ("superseded"),
                5 => ("Cessation Of Operation"),
                6 => ("Certificate Hold"),
                9 => ("Privilege With drawn"),
                _ => ("Unknown"),
            };
        }
        public static string ShowExtensions(X509Certificate Certificate)
        {
            string Info = "Extensions:" + Environment.NewLine;

            X509Extensions Extensions = Certificate.CertificateStructure.TbsCertificate.Extensions;
            foreach (var v in Extensions.GetExtensionOids())
            {

                X509Extension extension = Extensions.GetExtension(v);
                System.Security.Cryptography.X509Certificates.X509Extension x509 = new System.Security.Cryptography.X509Certificates.X509Extension(v.Id, extension.Value.GetOctets(), extension.IsCritical);

                // Console.WriteLine(x509.Format(true));
                if (x509.Oid.Value == "2.5.29.15")
                {
                    System.Security.Cryptography.X509Certificates.X509KeyUsageExtension ext = new System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(x509, x509.Critical);
                    Info += "\t";
                    Info += "KeyUsages " + x509.Oid.Value + Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += ext.KeyUsages.ToString() + Environment.NewLine;
                }

                if (x509.Oid.Value == "2.5.29.19")
                {
                    System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension ext = new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(x509, x509.Critical);
                    Info += "\t";
                    Info += "BasicConstraints " + x509.Oid.Value + Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += "CertificateAuthority:" + ext.CertificateAuthority.ToString() + Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += "HasPathLengthConstraint:" + ext.HasPathLengthConstraint.ToString() + Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += "PathLengthConstraint:" + ext.PathLengthConstraint.ToString() + Environment.NewLine;

                }

                if (x509.Oid.Value == "2.5.29.14")
                {
                    System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension ext = new System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension(x509, x509.Critical);
                    Info += "\t";
                    Info += "SubjectKeyIdentifier " + x509.Oid.Value + Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += ext.SubjectKeyIdentifier.ToString() + Environment.NewLine;

                }

                if (x509.Oid.Value == "2.5.29.37")
                {
                    System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension ext = new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(x509, x509.Critical);
                    System.Security.Cryptography.OidCollection oids = ext.EnhancedKeyUsages;
                    Info += "\t";
                    Info += "ExtendedKeyUsage " + x509.Oid.Value + Environment.NewLine;
                    foreach (System.Security.Cryptography.Oid oid in oids)
                    {
                        Info += "\t"; Info += "\t";
                        Info += oid.FriendlyName + " " + oid.Value + Environment.NewLine;

                    }

                }
            }

            return Info;
        }

        public static string ShowExtensions(Pkcs10CertificationRequest pkcs10)
        {
            string Info = "Extensions:" + Environment.NewLine;
           
            X509Extensions Extensions = GetX509ExtensionsFromCsr(pkcs10);
            foreach (var v in Extensions.GetExtensionOids())
            {

                X509Extension extension = Extensions.GetExtension(v);
                System.Security.Cryptography.X509Certificates.X509Extension x509 = new System.Security.Cryptography.X509Certificates.X509Extension(v.Id, extension.Value.GetOctets(), extension.IsCritical);
               
                // Console.WriteLine(x509.Format(true));
                if (x509.Oid.Value == "2.5.29.15")
                {
                    System.Security.Cryptography.X509Certificates.X509KeyUsageExtension ext = new System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(x509, x509.Critical);
                    Info += "\t";
                    Info += "KeyUsages "+ x509.Oid.Value+ Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += ext.KeyUsages.ToString()+ Environment.NewLine;  
                }

                if (x509.Oid.Value == "2.5.29.19")
                {
                    System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension ext = new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(x509, x509.Critical);
                    Info += "\t";
                    Info += "BasicConstraints "+ x509.Oid.Value + Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += "CertificateAuthority:"+ ext.CertificateAuthority.ToString() + Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += "HasPathLengthConstraint:"+ ext.HasPathLengthConstraint.ToString() + Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += "PathLengthConstraint:"+ ext.PathLengthConstraint.ToString() + Environment.NewLine;
                   
                }

                if (x509.Oid.Value == "2.5.29.14")
                {
                    System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension ext = new System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension(x509, x509.Critical);
                    Info += "\t";
                    Info += "SubjectKeyIdentifier "+ x509.Oid.Value + Environment.NewLine;
                    Info += "\t"; Info += "\t";
                    Info += ext.SubjectKeyIdentifier.ToString() + Environment.NewLine;
                    
                }

                if (x509.Oid.Value == "2.5.29.37")
                {
                    System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension ext = new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(x509, x509.Critical);
                    System.Security.Cryptography.OidCollection oids = ext.EnhancedKeyUsages;
                    Info += "\t";
                    Info += "ExtendedKeyUsage "+ x509.Oid.Value + Environment.NewLine;
                    foreach (System.Security.Cryptography.Oid oid in oids)
                    {
                        Info += "\t"; Info += "\t";
                        Info +=oid.FriendlyName+" "+oid.Value+Environment.NewLine;
                        
                    }
                    
                }
            }
            
            return Info;
        }

      public static  X509Extensions GetX509ExtensionsFromCsr(Pkcs10CertificationRequest certificateSigningRequest)
        {
            CertificationRequestInfo certificationRequestInfo = certificateSigningRequest.GetCertificationRequestInfo();
           
            Asn1Set attributesAsn1Set = certificationRequestInfo.Attributes;
            X509Extensions certificateRequestExtensions = null;
            for (int i = 0; i < attributesAsn1Set.Count; ++i)
            {
               Asn1Encodable asn1Encodable = attributesAsn1Set[i];
                Org.BouncyCastle.Asn1.Cms.Attribute attribute = Org.BouncyCastle.Asn1.Cms.Attribute.GetInstance(asn1Encodable);
             //  Org.BouncyCastle.Asn1.Cms.Attribute attribute = (Org.BouncyCastle.Asn1.Cms.Attribute)asn1Encodable;

                if (attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                {
                    
                    Asn1Set attributeValues = attribute.AttrValues;

                   
                    if (attributeValues.Count >= 1)
                    {

                        certificateRequestExtensions = X509Extensions.GetInstance(attributeValues[0]);
                       //  certificateRequestExtensions = (X509Extensions)attributeValues[0];
                       
                        break;
                    }
                }
            }
        
    

                return certificateRequestExtensions;
        }
        public static byte[] CrlReader(string CLR)
        {
            TextReader textReader = new StringReader(CLR);
            PemReader pemReader = new PemReader(textReader);
            return pemReader.ReadPemObject().Content;
        }
        public static byte[] CsrReader(string Csr)
        {
            TextReader textReader = new StringReader(Csr);
            PemReader pemReader = new PemReader(textReader);
             return pemReader.ReadPemObject().Content;
        }
        public static byte[] CertReader(string Cert)
        {
            TextReader textReader = new StringReader(Cert);
            PemReader pemReader = new PemReader(textReader);
            return pemReader.ReadPemObject().Content;
        }
        public static string CsrWriter(Pkcs10CertificationRequest Csr)
        {

            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(Csr);
            pemWriter.Writer.Flush();
            string str = textWriter.ToString();
            str = str.Remove(str.LastIndexOf(Environment.NewLine));
            return (str);
        }

        public static string CertWriter(X509Certificate Cert)
        {

            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(Cert);
            pemWriter.Writer.Flush();
            string str = textWriter.ToString();
            str = str.Remove(str.LastIndexOf(Environment.NewLine));
            return (str);
        }

        public static string CrlWriter(X509Crl CLR)
        {

            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(CLR);
            pemWriter.Writer.Flush();
            string str = textWriter.ToString();
            str = str.Remove(str.LastIndexOf(Environment.NewLine));
            return (str);
        }

        public static Pkcs10CertificationRequest CertRequest(X509Name SubjectDN,
                                                             String[] subjectAlternativeNames,
                                                             AsymmetricCipherKeyPair Key,
                                                             string algorithm,
                                                             KeyUsage KeyUsage,
                                                             KeyPurposeID[] ExtendedKeyUsage,
                                                             bool isCertificateAuthority)
        {
           // if(!algorithm.Contains("SHA3-")) algorithm = algorithm.Remove(algorithm.IndexOf("-"), 1);
            X509ExtensionsGenerator generator = new X509ExtensionsGenerator();
            AddKeyUsage(generator, KeyUsage);
            AddExtendedKeyUsage(generator, ExtendedKeyUsage);
            AddSubjectAlternativeNames(generator, subjectAlternativeNames);
            AddSubjectKeyIdentifier(generator, Key);
            AddBasicConstraints(generator, isCertificateAuthority);
            Org.BouncyCastle.Asn1.Cms.Attribute attributes = new Org.BouncyCastle.Asn1.Cms.Attribute(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(generator.Generate()));
            Pkcs10CertificationRequest pkcs10 = new Pkcs10CertificationRequest(algorithm, SubjectDN, Key.Public, new DerSet(attributes), Key.Private);
            //CertificationRequestInfo certificationRequestInfo = pkcs10.GetCertificationRequestInfo();
            //CertificationRequest request = new CertificationRequest(certificationRequestInfo, pkcs10.SignatureAlgorithm, pkcs10.Signature);
            
            return pkcs10;
        }
       
       
        public static X509Certificate SigneTbs(TbsCertificateStructure tbs,
                                               X509Certificate RootCA,
                                               AsymmetricKeyParameter CAKey)
        {
            SecureRandom Random = new SecureRandom();
            ISignatureFactory signatureCalculatorFactory = new Asn1SignatureFactory(RootCA.SigAlgOid, CAKey, Random);
            String algorithm = RootCA.SigAlgName;
            if(!algorithm.Contains("SHA3-")) algorithm = algorithm.Remove(algorithm.IndexOf("-"), 1);
            AlgorithmIdentifier algorithm1 = new DefaultSignatureAlgorithmIdentifierFinder().Find(algorithm);
            byte[] encoded = tbs.GetDerEncoded();
            IStreamCalculator streamCalculator = signatureCalculatorFactory.CreateCalculator();
            streamCalculator.Stream.Write(encoded, 0, encoded.Length);
            streamCalculator.Stream.Dispose();
            byte[] signature = ((IBlockResult)streamCalculator.GetResult()).Collect();
            DerBitString bitSig = new DerBitString(signature);
            X509CertificateStructure structure = new X509CertificateStructure(tbs, algorithm1, bitSig);
            return new X509Certificate(structure);
        }
       
        public static X509Certificate RenewCertificate(X509Certificate Certificate,AsymmetricKeyParameter CAkey)
        {
            X509V3CertificateGenerator Generator = new X509V3CertificateGenerator();
            Generator.SetSerialNumber(Certificate.SerialNumber);
           
            Generator.SetIssuerDN(Certificate.IssuerDN);
            Generator.SetSubjectDN(Certificate.SubjectDN);
            Generator.SetNotBefore(Certificate.NotAfter);
            Generator.SetPublicKey(Certificate.GetPublicKey());
            Generator.SetNotAfter(Certificate.NotAfter.Add(Certificate.NotAfter - Certificate.NotBefore));
           
            X509Extensions extensions = Certificate.CertificateStructure.TbsCertificate.Extensions;
            KeyUsage keyUsage = KeyUsage.FromExtensions(extensions);
            if (keyUsage != null) AddKeyUsage(Generator, keyUsage);

            ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.FromExtensions(extensions);
            if (extendedKeyUsage != null && extendedKeyUsage.Count > 0)
            {
                AddExtendedKeyUsage(Generator, extendedKeyUsage);
            }
            string Sig = Certificate.SigAlgName;

           
            if (!Sig.Contains("SHA3-")) Sig = Sig.Remove(Sig.IndexOf("-"), 1);
            SecureRandom random = new SecureRandom();
            
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(Sig,CAkey,random);
            X509Certificate Cert = Generator.Generate(signatureFactory);
            return (Cert);

        }

        public static X509Crl CreateClr(X509Certificate RootCA, X509Certificate Certificate,int Reason, AsymmetricKeyParameter CAkey)
        {
            X509V2CrlGenerator crlGenerator = new X509V2CrlGenerator();
            DateTime dateTime = DateTime.UtcNow;
            crlGenerator.SetIssuerDN(RootCA.IssuerDN);
            crlGenerator.SetThisUpdate(dateTime);
            crlGenerator.SetNextUpdate(dateTime.AddMonths(1));
            crlGenerator.AddCrlEntry(Certificate.SerialNumber, dateTime, Reason);
            crlGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(RootCA));
            crlGenerator.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.One));
            string algorithme = RootCA.SigAlgName;
            if (!algorithme.Contains("SHA3-")) algorithme = algorithme.Remove(algorithme.IndexOf("-"), 1);
            SecureRandom random = new SecureRandom();
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(algorithme,CAkey, random);
            
            return crlGenerator.Generate(signatureFactory);
        }
        public static X509Crl UpdateClr(X509Certificate RootCA, X509Certificate Certificate, int Reason,X509Crl crl ,AsymmetricKeyParameter CAkey)
        {
            Console.WriteLine("entring UpdateClr");
            X509V2CrlGenerator crlGenerator = new X509V2CrlGenerator();
            DateTime dateTime = DateTime.UtcNow;
            crlGenerator.SetIssuerDN(RootCA.IssuerDN);
            crlGenerator.SetThisUpdate(dateTime);
            crlGenerator.SetNextUpdate(dateTime.AddMonths(1));
            crlGenerator.AddCrl(crl);
            crlGenerator.AddCrlEntry(Certificate.SerialNumber, dateTime, Reason);
            crlGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(RootCA));
            Asn1OctetString octetString = crl.GetExtensionValue(X509Extensions.CrlNumber);
            long number = CrlNumber.GetInstance(X509ExtensionUtilities.FromExtensionValue(octetString)).LongValueExact;
            BigInteger serial = BigInteger.ValueOf(number+1);
            
            crlGenerator.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(serial));
            string algorithme = RootCA.SigAlgName;
            if (!algorithme.Contains("SHA3-")) algorithme = algorithme.Remove(algorithme.IndexOf("-"), 1);
            SecureRandom random = new SecureRandom();
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(algorithme, CAkey, random);
            return crlGenerator.Generate(signatureFactory);
        }
        public static X509Certificate RootCA(BigInteger SerialNumber,
                                             AsymmetricCipherKeyPair KeyPair,
                                             string SubjectName,
                                             string[] SubjectAlternativeNames,
                                             KeyUsage KeyUsage,
                                             KeyPurposeID[] ExtendedKeyUsage,
                                             string algorithm,
                                             int Validity)
        {
           // if(!algorithm.Contains("SHA3-")) algorithm = algorithm.Remove(algorithm.IndexOf("-"), 1);
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetSerialNumber(SerialNumber);
            certificateGenerator.SetIssuerDN(new X509Name(SubjectName));
            certificateGenerator.SetSubjectDN(new X509Name(SubjectName));
            DateTime dateTime = DateTime.UtcNow;
            certificateGenerator.SetNotBefore(dateTime);
            certificateGenerator.SetNotAfter(dateTime.AddYears(Validity));
            certificateGenerator.SetPublicKey(KeyPair.Public);
            AddAuthorityKeyIdentifier(certificateGenerator, new X509Name(SubjectName), KeyPair, SerialNumber);
            AddSubjectKeyIdentifier(certificateGenerator, KeyPair);
            AddBasicConstraints(certificateGenerator, true);

            if (KeyUsage != null)
                AddKeyUsage(certificateGenerator, KeyUsage);

            if (ExtendedKeyUsage != null && ExtendedKeyUsage.Any())
                AddExtendedKeyUsage(certificateGenerator, ExtendedKeyUsage);

            if (SubjectAlternativeNames != null && SubjectAlternativeNames.Any())
                AddSubjectAlternativeNames(certificateGenerator, SubjectAlternativeNames);
            SecureRandom random = new SecureRandom();
          
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(algorithm, KeyPair.Private, random);
            
            X509Certificate certificate = certificateGenerator.Generate(signatureFactory);
            return (certificate);
        }
        public static TbsCertificateStructure TbsCertificate(Pkcs10CertificationRequest Csr,
                                                             int Validity,
                                                             BigInteger SubjectSerialNumber,
                                                             X509Certificate RootCA
                                                             )
        {

            
            V3TbsCertificateGenerator tbsGenerator = new V3TbsCertificateGenerator();            
            tbsGenerator.SetSubject(Csr.GetCertificationRequestInfo().Subject);
            tbsGenerator.SetIssuer(RootCA.SubjectDN);
            tbsGenerator.SetSerialNumber(new DerInteger(SubjectSerialNumber));
            tbsGenerator.SetSubjectPublicKeyInfo(Csr.GetCertificationRequestInfo().SubjectPublicKeyInfo);
            string s = RootCA.SigAlgName;
            if(!s.Contains("SHA3-")) s = s.Remove(s.IndexOf("-"), 1);

            AlgorithmIdentifier algorithm = new DefaultSignatureAlgorithmIdentifierFinder().Find(s);
            tbsGenerator.SetSignature(algorithm);
            DateTime dateTime = DateTime.UtcNow;
            tbsGenerator.SetStartDate(new DerUtcTime(dateTime));
            tbsGenerator.SetEndDate(new DerUtcTime(dateTime.AddYears(Validity)));
       
            tbsGenerator.SetExtensions(GetX509ExtensionsFromCsr(Csr));
          
            return tbsGenerator.GenerateTbsCertificate();
        }
        


        public static string GeneratePassword(int size)
        {
            string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            StringBuilder pass = new StringBuilder();
            for(int i=0;i<size;i++)
            {
                
                var num = BigIntegers.CreateRandomInRange(
                    BigInteger.Zero, BigInteger.ValueOf(valid.Length-1), new SecureRandom());
                
                pass.Append(valid[int.Parse(num.ToString())]);
            }
            
            return pass.ToString();
        }
        public static BigInteger GenerateSerialNumber(SecureRandom random)
        {
            var serialNumber =
                BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            return serialNumber;
        }
        public static void AddAuthorityKeyIdentifier(X509V3CertificateGenerator certificateGenerator,
                                                     X509Name issuerDN,
                                                     AsymmetricCipherKeyPair issuerKeyPair,
                                                     BigInteger issuerSerialNumber)
        {
            var authorityKeyIdentifierExtension =
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Public));
            //                    new GeneralNames(new GeneralName(issuerDN)),
            //                   issuerSerialNumber);
            certificateGenerator.AddExtension(
                X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifierExtension);
        }

        public static void AddBasicConstraints(X509V3CertificateGenerator certificateGenerator,
                                               bool isCertificateAuthority)
        {
            certificateGenerator.AddExtension(
                X509Extensions.BasicConstraints.Id, true, new BasicConstraints(isCertificateAuthority));
        }
        public static void AddSubjectKeyIdentifier(X509V3CertificateGenerator certificateGenerator,
                                                    AsymmetricCipherKeyPair subjectKeyPair)
        {
            var subjectKeyIdentifierExtension =
                new SubjectKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public));
            certificateGenerator.AddExtension(
                X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifierExtension);
        }

        public static void AddExtendedKeyUsage(X509V3CertificateGenerator certificateGenerator, KeyPurposeID[] usages)
        {

            certificateGenerator.AddExtension(
                X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(usages));

        }
        public static void AddExtendedKeyUsage(X509V3CertificateGenerator certificateGenerator, ExtendedKeyUsage extendedKeyUsage)
        {

            certificateGenerator.AddExtension(
                X509Extensions.ExtendedKeyUsage.Id, false, extendedKeyUsage);

        }
       
        public static void AddKeyUsage(X509V3CertificateGenerator certificateGenerator, KeyUsage usages)
        {
            certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, false, usages.ToAsn1Object());

        }

        public static void AddSubjectAlternativeNames(X509V3CertificateGenerator certificateGenerator,
                                                      IEnumerable<string> subjectAlternativeNames)
        {
            List<Asn1Encodable> Entries = new List<Asn1Encodable>();
          
           
            foreach (string subjectAlternativeName in subjectAlternativeNames)
            {
                // Test if an IP Address
                IPAddress ip = null;
                if (IPAddress.TryParse(subjectAlternativeName, out ip))
                {
                    Entries.Add(new GeneralName(GeneralName.IPAddress, subjectAlternativeName));
                }
                else
                {
                    Entries.Add(new GeneralName(GeneralName.DnsName, subjectAlternativeName));
                    
                }
               
            }
           
            DerSequence subjectAlternativeNamesExtension = new DerSequence(Entries.ToArray());
            certificateGenerator.AddExtension(
            X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);
        }
        public static  void AddAuthorityKeyIdentifier(X509ExtensionsGenerator ExtensionsGenerator,
                                                     X509Name issuerDN,
                                                     AsymmetricCipherKeyPair issuerKeyPair,
                                                     BigInteger issuerSerialNumber)
        {
            var authorityKeyIdentifierExtension =
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Public));
            //                    new GeneralNames(new GeneralName(issuerDN)),
            //                   issuerSerialNumber);
            ExtensionsGenerator.AddExtension(
                X509Extensions.AuthorityKeyIdentifier, false, authorityKeyIdentifierExtension);
        }

        public static void AddBasicConstraints(X509ExtensionsGenerator ExtensionsGenerator,
                                               bool isCertificateAuthority)
        {
            ExtensionsGenerator.AddExtension(
                X509Extensions.BasicConstraints, true, new BasicConstraints(isCertificateAuthority));
        }

        public static void AddSubjectKeyIdentifier(X509ExtensionsGenerator ExtensionsGenerator,
                                                    AsymmetricCipherKeyPair subjectKeyPair)
        {
            var subjectKeyIdentifierExtension =
                new SubjectKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public));
            ExtensionsGenerator.AddExtension(
                X509Extensions.SubjectKeyIdentifier, false, subjectKeyIdentifierExtension);
        }

        public static void AddExtendedKeyUsage(X509ExtensionsGenerator ExtensionsGenerator, KeyPurposeID[] usages)
        {

            ExtensionsGenerator.AddExtension(
                X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(usages));

        }

        public static void AddKeyUsage(X509ExtensionsGenerator ExtensionsGenerator, KeyUsage usages)
        {
            ExtensionsGenerator.AddExtension(X509Extensions.KeyUsage, false, usages.ToAsn1Object());
        }

        public static void AddSubjectAlternativeNames(X509ExtensionsGenerator ExtensionsGenerator,
                                                       IEnumerable<string> subjectAlternativeNames)
        {
            List<Asn1Encodable> sanEntries = new List<Asn1Encodable>();
            foreach (string subjectAlternativeName in subjectAlternativeNames)
            {
                // Test if an IP Address
                IPAddress ip = null;
                if (IPAddress.TryParse(subjectAlternativeName, out ip))
                {
                    sanEntries.Add(new GeneralName(GeneralName.IPAddress, subjectAlternativeName));
                }
                else
                {
                    sanEntries.Add(new GeneralName(GeneralName.DnsName, subjectAlternativeName));
                }

               
            }
            DerSequence subjectAlternativeNamesExtension = new DerSequence(sanEntries.ToArray());
            ExtensionsGenerator.AddExtension(
            X509Extensions.SubjectAlternativeName, false, subjectAlternativeNamesExtension);
        }
    }
}
