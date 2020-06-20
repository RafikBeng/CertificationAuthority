using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.X509;
using RegistrationAuthority.Models;
using RegistrationAuthority.Services;
using static Certlib.KeyGen;
using static Certlib.CertGen;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace RegistrationAuthority.Controllers
{
    public class CertController : Controller
    {
        private readonly CsrService _CsrService;
        public CertController(CsrService CsrService)
        {
            _CsrService = CsrService;
        }
        // GET: CertController
        public ActionResult Index()
        {
            return View(_CsrService.GetCerts());
        }

        // GET: CertController/Details/5
        public ActionResult Details(long Serial)
        {
            CertModel result = _CsrService.GetCert(Serial);
            X509Certificate Certificate = new X509CertificateParser().ReadCertificate(CertReader(result.Certificat));
            result.Thumbprint = Hex.ToHexString(Certificate.GetSignature());
            result.Extensions = ShowExtensions(Certificate);
            result.Publickey = KeyWriter(Certificate.GetPublicKey());
            result.Signature = Certificate.SigAlgName;
            
            AsymmetricKeyParameter key = Certificate.GetPublicKey();
            if (Certificate.SigAlgName.Contains("RSA"))
            {
                result.Algorithme = "RSA";
                RsaKeyParameters rsaKey = (RsaKeyParameters)key;
                result.KeySize = rsaKey.Modulus.BitLength;
            }
            else
            {
                result.Algorithme = "ECC";
                ECPublicKeyParameters publicKeyParam = (ECPublicKeyParameters)key;
                result.KeySize = publicKeyParam.Parameters.Curve.FieldSize;
            }
            return View(result);

        }

        // GET: CertController/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: CertController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: CertController/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: CertController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: CertController/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: CertController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}
