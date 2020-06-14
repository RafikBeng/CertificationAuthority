using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certificationauthority.Models;
using Certificationauthority.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto;

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
            CertModel Cert = _CertService.GetCert(service.Serial);
            
           
            return View();
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
        public ActionResult Delete(int id)
        {
            return View();
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