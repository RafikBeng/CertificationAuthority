using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace RegistrationAuthority.Controllers
{
    public class TbsController : Controller
    {
        // GET: Tbs
        public ActionResult Index()
        {
            return View();
        }

        // GET: Tbs/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: Tbs/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Tbs/Create
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

        // GET: Tbs/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: Tbs/Edit/5
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

        // GET: Tbs/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: Tbs/Delete/5
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