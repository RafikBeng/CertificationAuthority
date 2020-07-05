using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Certificationauthority.Models;
using Certificationauthority.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using static Certlib.CertGen;
using static Certlib.KeyGen;
namespace Certificationauthority.Controllers
{
    public class CsrController : Controller
    {
        private readonly CertService _CertService;
        public CsrController(CertService CertService)
        {
            _CertService = CertService;
        }
        // GET: ListCsr
        public ActionResult Index()
        {
            return View(_CertService.GetCsrs());
        }

        // GET: ListCsr/Details/5
        public ActionResult Details(string id)
        {
           
            CsrModel result = _CertService.GetCsr(id);
           
            Pkcs10CertificationRequest pkcs10 = new Pkcs10CertificationRequest(CsrReader(result.Certificat));
            string Sig = SignerUtilities.GetEncodingName(pkcs10.SignatureAlgorithm.Algorithm);



            CertModel Model = new CertModel
            {
                SubjectDN = pkcs10.GetCertificationRequestInfo().Subject.ToString(),
                Thumbprint = Hex.ToHexString(pkcs10.Signature.GetOctets()),
                Extensions = ShowExtensions(pkcs10),
                Publickey = KeyWriter(pkcs10.GetPublicKey()),
                Privatekey = result.Privatekey,
                Signature = Sig,
                Id = id,
                Validity = result.Validity,
                Certificat = result.Certificat,
                Password = result.Password
            };
            AsymmetricKeyParameter key = pkcs10.GetPublicKey();
            if (Sig.Contains("RSA"))
            {
                Model.Algorithme = "RSA";
                
                RsaKeyParameters rsaKey = (RsaKeyParameters)key;
               // RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)key);
                Model.KeySize = rsaKey.Modulus.BitLength;
            }
            else
            {
                Model.Algorithme = "ECC";

                ECPublicKeyParameters publicKeyParam = (ECPublicKeyParameters)key;
                Model.KeySize = publicKeyParam.Parameters.Curve.FieldSize;
               
            }
                return View(Model);
        }

        // GET: ListCsr/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: ListCsr/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                // TODO: Add insert logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: ListCsr/Edit/5
        public ActionResult Validate(String id)
        {
            CsrModel result = _CertService.GetCsr(id);
            
            Pkcs10CertificationRequest pkcs10 = new Pkcs10CertificationRequest(CsrReader(result.Certificat));
            CertModel cert = _CertService.GetCert(true);
            byte[] bits = CertReader(cert.Certificat);
            X509Certificate RootCA = new X509CertificateParser().ReadCertificate(bits);
            //BigInteger SerialNumber = GenerateSerialNumber(new SecureRandom());
            long serial = _CertService.GetMaxSerial();
            var Crls = _CertService.GetClrs();
            if(Crls.Count()> 0)
            {
                long Max_Crl_serial = _CertService.MaxSerial();
                CrlModel LastCrl = _CertService.GetCrl(Max_Crl_serial);
                X509Crl crl = new X509CrlParser().ReadCrl(CrlReader(LastCrl.Content));
                var RevokedCertificates = crl.GetRevokedCertificates();
                Array array= Array.CreateInstance(typeof(X509CrlEntry),RevokedCertificates.Count);
                RevokedCertificates.CopyTo(array,0);
                X509CrlEntry entry = (X509CrlEntry)array.GetValue(RevokedCertificates.Count-1);
               
               
                if (entry.SerialNumber.LongValue > serial) serial = entry.SerialNumber.LongValue;
            }
            
            
            BigInteger SerialNumber = BigInteger.ValueOf(serial + 1);
            TbsCertificateStructure tbs = TbsCertificate(pkcs10, int.Parse(result.Validity), SerialNumber, RootCA);
            X509Certificate certificate = SigneTbs(tbs, RootCA, PrivateKeyReader(cert.Privatekey));
            CertModel model = new CertModel
            {
                Privatekey = result.Privatekey,
                Serial = Int64.Parse(SerialNumber.ToString()),
                Certificat = CertWriter(certificate),
                IsRootCA = false,
                NotAfter = certificate.NotAfter,
                NotBefore = certificate.NotBefore,
                SubjectDN = certificate.SubjectDN.ToString(),
                IssuerDN = certificate.IssuerDN.ToString(),
                Thumbprint = Hex.ToHexString(certificate.GetSignature()),
                Extensions = ShowExtensions(certificate),
                Signature = certificate.SigAlgName,
                Publickey = KeyWriter(certificate.GetPublicKey()),
                Password = result.Password
            };
         
            string sigalgo = SignerUtilities.GetEncodingName(pkcs10.SignatureAlgorithm.Algorithm);
            AsymmetricKeyParameter key = pkcs10.GetPublicKey();
            if (sigalgo.Contains("RSA"))
            {
                model.Algorithme = "RSA";
                RsaKeyParameters pubkey = (RsaKeyParameters)key;
                model.KeySize = pubkey.Modulus.BitLength;
            }
            else
            {
                model.Algorithme = "EC";
                ECKeyParameters keyParameters = (ECKeyParameters)key;
                model.KeySize = keyParameters.Parameters.Curve.FieldSize;
            }
            _CertService.Create(model);
            _CertService.DelCsr(id);
            return View("../Cert/Details", model);
        }

        // POST: ListCsr/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Validate(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add update logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: ListCsr/Delete/5
        public ActionResult Delete(String id)
        {
            _CertService.DelCsr(id);
            return RedirectToAction(nameof(Index));
        }

        // POST: ListCsr/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add delete logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}