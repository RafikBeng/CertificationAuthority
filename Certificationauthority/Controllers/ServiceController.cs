using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certificationauthority.Models;
using Certificationauthority.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using static Certlib.CertGen;
using static Certlib.KeyGen;
namespace Certificationauthority.Controllers
{
    public class ServiceController : Controller
    {
        private readonly CertService _CertService;
        public ServiceController(CertService CertService)
        {
            _CertService = CertService;
        }
        // GET: Service
        public JsonResult CheckPassword(Int64 Serial)
        {
            CertModel Cert = _CertService.GetCert(Serial);
            if (Cert != null) return Json(new { s = Cert.Password });
            else return Json(new { s = "not found" });
        }
        public ActionResult Index()
        {
            return View(_CertService.GetServices());
        }

        // GET: Service/Details/5
        public ActionResult Details(string id)
        {
            ServiceModel model = _CertService.GetService(id);
            int reason = int.Parse(model.Reason);
            switch (reason)
            {
                case 0: 
                    model.Reason = "unspecified";
                    break;
                case 1: 
                    model.Reason = "key Compromise";
                    break;
                case 3:
                    model.Reason = "Affiliation Changed";
                    break;
                case 4: 
                    model.Reason = "superseded";
                    break;
                case 5: 
                    model.Reason = "Cessation Of Operation";
                    break;
                case 6: 
                    model.Reason = "Certificate Hold";
                    break;
                case 9: 
                    model.Reason = "Privilege With drawn";
                    break;
                default:
                    break;
            }
            return View(model);
        }

        // GET: Service/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Service/Create
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

        // GET: Service/Edit/5
        public ActionResult Validate(string id)
        {
            ServiceModel service = _CertService.GetService(id);
            _CertService.DelServices(id);
            CertModel Cert = _CertService.GetCert(service.Serial);
            byte[] bits = CertReader(Cert.Certificat);
            X509Certificate certificate = new X509CertificateParser().ReadCertificate(bits);
            if (service.Object == "Renew")
            {
                CertModel RootCa = _CertService.GetCert(true);
                AsymmetricKeyParameter key = PrivateKeyReader(RootCa.Privatekey);
                X509Certificate NewCertificate = RenewCertificate(certificate, key);
                Cert.NotAfter = NewCertificate.NotAfter;
                Cert.NotBefore = NewCertificate.NotBefore;
                _CertService.DelCert(Cert.Id);
                _CertService.Create(Cert);
                return View("Validate_Cert",Cert);
            }
            else if (service.Object == "Revoke")
            {
                CrlModel model = new CrlModel();
                var Crls = _CertService.GetClrs();
                CertModel Root = _CertService.GetCert(true);
                byte[] bits1 = CertReader(Root.Certificat);
                X509Certificate RootCA = new X509CertificateParser().ReadCertificate(bits1);
                AsymmetricKeyParameter key = PrivateKeyReader(Root.Privatekey);
                if (Crls == null)
                {
                    X509Crl crl = CreateClr(RootCA, certificate, int.Parse(service.Reason), key);
                    Asn1OctetString octetString = crl.GetExtensionValue(X509Extensions.CrlNumber);
                    long number = CrlNumber.GetInstance(X509ExtensionUtilities.FromExtensionValue(octetString)).LongValueExact;
                    model.Content = CrlWriter(crl);
                    model.ThisUpdate = crl.ThisUpdate;
                    model.NextUpdate = crl.NextUpdate.Value;
                    model.Serial = number;
                    model.Reason = service.Reason;
                    model.DN = crl.IssuerDN.ToString();
                }
                else
                {
                    long seriale = _CertService.MaxSeriale();
                    CrlModel LastCrl = _CertService.GetCrl(seriale);
                    X509Crl crl = new X509CrlParser().ReadCrl(CrlReader(LastCrl.Content));
                    X509Crl NewCrl = UpdateClr(RootCA, certificate, int.Parse(service.Reason), crl, key);
                    model.Content = CrlWriter(NewCrl);
                    model.ThisUpdate = NewCrl.ThisUpdate;
                    model.NextUpdate = NewCrl.NextUpdate.Value;
                    model.Serial = seriale;
                    model.Reason = service.Reason;
                    model.DN = crl.IssuerDN.ToString();

                }
                _CertService.DelCert(Cert.Id);
                _CertService.Create(model);
                return View("Validate_Crl",model);
            }
            else return View("Validate_Cert", Cert);


        }

        // POST: Service/Edit/5
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

        // GET: Service/Delete/5
        public ActionResult Delete(string id)
        {
            _CertService.DelServices(id);
            return View(nameof(Index));
        }

        // POST: Service/Delete/5
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