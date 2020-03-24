using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Certlib
{
    public static class CertGen
    {
        public static TbsCertificateStructure TbsCertificate(String SubjectDN,
                                                             String IssuerDN,
                                                             String[] subjectAlternativeNames,
                                                             AsymmetricCipherKeyPair SubjectKeyPair,
                                                             BigInteger SubjectSerialNumber,
                                                             KeyUsage KeyUsage,
                                                             KeyPurposeID[] ExtendedKeyUsage,
                                                             AlgorithmIdentifier SignatureAlgorithm,
                                                             int Validity,
                                                             bool isCertificateAuthority)
        {
            V3TbsCertificateGenerator tbsGenerator = new V3TbsCertificateGenerator();
            tbsGenerator.SetSubject(new X509Name(SubjectDN));
            tbsGenerator.SetIssuer(new X509Name(IssuerDN));
            tbsGenerator.SetSerialNumber(new DerInteger(SubjectSerialNumber));
            tbsGenerator.SetSignature(SignatureAlgorithm);
            tbsGenerator.SetSubjectPublicKeyInfo(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(SubjectKeyPair.Public));
            DateTime dateTime = DateTime.UtcNow;
            tbsGenerator.SetStartDate(new DerUtcTime(dateTime));
            tbsGenerator.SetEndDate(new DerUtcTime(dateTime.AddYears(Validity)));
            X509ExtensionsGenerator x509Extensions = new X509ExtensionsGenerator();
            AddBasicConstraints(x509Extensions, isCertificateAuthority);
            AddSubjectAlternativeNames(x509Extensions, subjectAlternativeNames);
            AddKeyUsage(x509Extensions, KeyUsage);
            AddExtendedKeyUsage(x509Extensions, ExtendedKeyUsage);
            tbsGenerator.SetExtensions(x509Extensions.Generate());
            return tbsGenerator.GenerateTbsCertificate();
        }


        public static BigInteger GenerateSerialNumber(SecureRandom random)
        {
            var serialNumber =
                BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            return serialNumber;
        }

        public static void AddAuthorityKeyIdentifier(X509ExtensionsGenerator ExtensionsGenerator,
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

                DerSequence subjectAlternativeNamesExtension = new DerSequence(sanEntries.ToArray());
                ExtensionsGenerator.AddExtension(
                X509Extensions.SubjectAlternativeName, false, subjectAlternativeNamesExtension);
            }
        }
    }
}
