using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.IO;

namespace Certlib
{
    public static class KeyGen
    {
       
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
            TextReader textReader = new StringReader(Key);
            PemReader pemReader = new PemReader(textReader);
            var KeyParameter = (AsymmetricCipherKeyPair) pemReader.ReadObject();
            return KeyParameter.Private;
        }
        public static AsymmetricKeyParameter PublicKeyReader(string Key)
        {
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
            RsaKeyGenerationParameters rsaKeyGenerationParameters = new RsaKeyGenerationParameters(publicExponent, secureRandom, keysize, 80);
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

        public static AsymmetricCipherKeyPair GenerateEcKeyPair(int KeySize, string algorithme = "ECDSA")
        {
            ECKeyPairGenerator EC = new ECKeyPairGenerator(algorithme);
            EC.Init(new KeyGenerationParameters(new SecureRandom(), KeySize));
            return (EC.GenerateKeyPair());
        }

    }
}
