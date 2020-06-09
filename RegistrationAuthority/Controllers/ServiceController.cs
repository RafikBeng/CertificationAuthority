using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using RegistrationAuthority.Models;
using RegistrationAuthority.Services;
using static Certlib.KeyGen;
namespace RegistrationAuthority.Controllers
{
    public class ServiceController : Controller
    {
        private readonly CsrService _CsrService;
        public ServiceController(CsrService CsrService)
        {
            _CsrService = CsrService;
        }
        // GET: Service
        public ActionResult Index()
        {
            return View();
        }

        // GET: Service/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: Service/Create
        public ActionResult Create()
        {
            ServiceModel model = new ServiceModel();
            return View(model);
        }

        // POST: Service/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(ServiceModel collection)
        {
            try
            {
                 collection.Password = GetHash(collection.Password);
                _CsrService.Create(collection);

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: Service/Edit/5
        public ActionResult Edit(int id)
        {
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