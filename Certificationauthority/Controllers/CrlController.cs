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
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using static Certlib.CertGen;
namespace Certificationauthority.Controllers
{
    public class CrlController : Controller
    {
        private readonly CertService _CertService;
        public CrlController(CertService CertService)
        {
            _CertService = CertService;
        }
        // GET: CrlController
        public ActionResult Index()
        {
            return View(_CertService.GetClrs());
        }

        // GET: CrlController/Details/5
        public ActionResult Details(long Serial)
        {
            CrlModel model = _CertService.GetCrl(Serial);
            X509Crl crl= new X509CrlParser().ReadCrl(CrlReader(model.Content));
            var RevokedCertificates=crl.GetRevokedCertificates();
            model.RevokedCertificates = new List<CrlEntryModel>();
            foreach(X509CrlEntry crlEntry in RevokedCertificates)
            {
                Asn1OctetString octetString = crlEntry.GetExtensionValue(X509Extensions.ReasonCode);
                DerEnumerated derEnumerated = (DerEnumerated)X509ExtensionUtilities.FromExtensionValue(octetString);
                int ReasonCode = derEnumerated.IntValueExact;
                CrlEntryModel model1 = new CrlEntryModel
                {
                    RevocationDate = crlEntry.RevocationDate,
                    Serial = crlEntry.SerialNumber.LongValue
                };
                model1.Reason = GetReasonCode(ReasonCode);
                model.RevokedCertificates.Add(model1);
            }
            return View(model);
        }

        // GET: CrlController/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: CrlController/Create
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

        // GET: CrlController/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: CrlController/Edit/5
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

        // GET: CrlController/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: CrlController/Delete/5
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
