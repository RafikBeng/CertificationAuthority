using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;
using System.Text;

namespace Certlib
{
    public static class KeyGen
    {
        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }
        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
        public static string ExportPublicKey(System.Security.Cryptography.RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN PUBLIC KEY-----\n");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END PUBLIC KEY-----");
            }

            return outputStream.ToString();
        }
        public static System.Security.Cryptography.RSACryptoServiceProvider ImportPrivateKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            System.Security.Cryptography.RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);

            System.Security.Cryptography.RSACryptoServiceProvider csp = new System.Security.Cryptography.RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }
        public static System.Security.Cryptography.RSACryptoServiceProvider ImportPublicKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
            System.Security.Cryptography.RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

            System.Security.Cryptography.RSACryptoServiceProvider csp = new System.Security.Cryptography.RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }
        public static string ExportPrivateKey(System.Security.Cryptography.RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN RSA PRIVATE KEY-----\n");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END RSA PRIVATE KEY-----");
            }

            return outputStream.ToString();
        }
        public static string GetHash(String pass)
        {
            byte[] message = Encoding.ASCII.GetBytes(pass);
            return Hex.ToHexString(DigestUtilities.CalculateDigest("SHA3-512", message));
        }

        public static string KeyWriter(AsymmetricKeyParameter Key)
        {
             
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(Key);
            pemWriter.Writer.Flush();
            string str = textWriter.ToString();
            str = str.Remove(str.LastIndexOf(Environment.NewLine));
            return (str);
        }
        public static AsymmetricKeyParameter PrivateKeyReader(string Key)
        {
           // Console.WriteLine(Key);
            TextReader textReader = new StringReader(Key);
            PemReader pemReader = new PemReader(textReader);
         
            var KeyParameter = (AsymmetricCipherKeyPair) pemReader.ReadObject();
            return KeyParameter.Private;
        }
        public static AsymmetricKeyParameter PublicKeyReader(string Key)
        {
           // Console.WriteLine(Key);
            TextReader textReader = new StringReader(Key);
            PemReader pemReader = new PemReader(textReader);
            var KeyParameter = (AsymmetricKeyParameter) pemReader.ReadObject();
            return KeyParameter;
        }
        public static AsymmetricCipherKeyPair GenerateElGamalKeyPair(int keysize)
        {
            SecureRandom secureRandom = new SecureRandom();
            ElGamalParametersGenerator gamalParametersGenerator = new ElGamalParametersGenerator();
            gamalParametersGenerator.Init(keysize, 80, secureRandom);
            ElGamalParameters elGamalParameters = gamalParametersGenerator.GenerateParameters();
            ElGamalKeyGenerationParameters elGamalKeyGenerationParameters = new ElGamalKeyGenerationParameters(secureRandom, elGamalParameters);
            ElGamalKeyPairGenerator elGamalKeyPairGenerator = new ElGamalKeyPairGenerator();
            elGamalKeyPairGenerator.Init(elGamalKeyGenerationParameters);
            return (elGamalKeyPairGenerator.GenerateKeyPair());
        }
        public static AsymmetricCipherKeyPair  GenerateDsaKeyPair(int keysize)
        {
            SecureRandom secureRandom = new SecureRandom();
            DsaParametersGenerator dsaParametersGenerator = new DsaParametersGenerator();
            dsaParametersGenerator.Init(keysize, 80, secureRandom);
            DsaParameters dsaParameters = dsaParametersGenerator.GenerateParameters();
            DsaKeyPairGenerator dsaKeyPairGenerator = new DsaKeyPairGenerator();
            DsaKeyGenerationParameters dsaKeyGenerationParameters = new DsaKeyGenerationParameters(secureRandom, dsaParameters);
            dsaKeyPairGenerator.Init(dsaKeyGenerationParameters);
            return (dsaKeyPairGenerator.GenerateKeyPair());
        }
        public static AsymmetricCipherKeyPair GenerateRsaKeyPair(int keysize)
        {
            BigInteger publicExponent = BigInteger.ValueOf(0x10001);
            SecureRandom secureRandom = new SecureRandom();
            RsaKeyGenerationParameters rsaKeyGenerationParameters = new RsaKeyGenerationParameters(publicExponent, secureRandom, keysize, 112);
            var keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(rsaKeyGenerationParameters);
            return keyGenerator.GenerateKeyPair();
        }

        public static AsymmetricCipherKeyPair GenerateRsaKeyPair(RsaKeyParameters parameters)
        {
            BigInteger publicExponent = BigInteger.ValueOf(0x10001);
            SecureRandom secureRandom = new SecureRandom();
            RsaKeyGenerationParameters rsaKeyGenerationParameters = new RsaKeyGenerationParameters(parameters.Exponent, secureRandom, parameters.Modulus.BitLength, 80);
            var keyGenerator = new RsaKeyPairGenerator();
            
            keyGenerator.Init(rsaKeyGenerationParameters);
            return keyGenerator.GenerateKeyPair();
        }

        public static AsymmetricCipherKeyPair GenerateEcKeyPair(string curveName, string algorithme = "ECDSA")
        {
            SecureRandom secureRandom = new SecureRandom();
          //  var ecParam = ECNamedCurveTable.GetByName(curveName);
            //     var ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N,ecParam.H);
           // var ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N, ecParam.H, ecParam.GetSeed());
            // var keygenParam = new ECKeyGenerationParameters(ecDomain, secureRandom);
            var keygenParam = new ECKeyGenerationParameters(ECNamedCurveTable.GetOid(curveName), secureRandom);
            var keyGenerator = new ECKeyPairGenerator(algorithme);
            keyGenerator.Init(keygenParam);
            return keyGenerator.GenerateKeyPair();
        }
        public static AsymmetricCipherKeyPair GenerateEcKeyPair(ECKeyParameters KeyParam, string algorithme = "ECDSA")
        {
            SecureRandom secureRandom = new SecureRandom();
            //  var ecParam = ECNamedCurveTable.GetByName(curveName);
            //     var ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N,ecParam.H);
            // var ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N, ecParam.H, ecParam.GetSeed());
            // var keygenParam = new ECKeyGenerationParameters(ecDomain, secureRandom);
           
            var keygenParam = new ECKeyGenerationParameters(KeyParam.PublicKeyParamSet, secureRandom);
            var keyGenerator = new ECKeyPairGenerator(algorithme);
            keyGenerator.Init(keygenParam);
            return keyGenerator.GenerateKeyPair();
        }

        public static AsymmetricCipherKeyPair GenerateEcKeyPair(int KeySize, string algorithme = "ECDSA")
        {
            ECKeyPairGenerator EC = new ECKeyPairGenerator(algorithme);
            EC.Init(new KeyGenerationParameters(new SecureRandom(), KeySize));
            return (EC.GenerateKeyPair());
        }

    }
}
