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
            CertModel Model = new CertModel
            {
                SubjectDN = Certificate.SubjectDN.ToString(),
                IssuerDN = Certificate.IssuerDN.ToString(),
                Thumbprint = Hex.ToHexString(Certificate.GetSignature()),
                Extensions = ShowExtensions(Certificate),
                Publickey = KeyWriter(Certificate.GetPublicKey()),
               // Privatekey = result.Privatekey,
                Signature = Certificate.SigAlgName,
                Serial = Serial,
                Validity = result.Validity,
                Certificat = result.Certificat,
                Password = result.Password
            };
            AsymmetricKeyParameter key = Certificate.GetPublicKey();
            if (Certificate.SigAlgName.Contains("RSA"))
            {
                Model.Algorithme = "RSA";
                RsaKeyParameters rsaKey = (RsaKeyParameters)key;
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
