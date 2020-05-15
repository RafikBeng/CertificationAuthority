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
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
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
                Thumbprint = Convert.ToBase64String(pkcs10.Signature.GetOctets()),
                Extensions = ShowExtensions(pkcs10),
                Publickey = KeyWriter(pkcs10.GetPublicKey()),
                Privatekey = result.Privatekey,
                Signature = Sig,
               
                Validity=result.Validity,
                Certificat= result.Certificat,
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
                Model.Algorithme = "ECDSA";

                ECPublicKeyParameters publicKeyParam = (ECPublicKeyParameters)key;
                Model.KeySize = publicKeyParam.Parameters.Curve.FieldSize;
               // publicKeyParam.Parameters.
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
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: ListCsr/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
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
        public ActionResult Delete(int id)
        {
            return View();
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