using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using RegistrationAuthority.Models;
using static Certlib.KeyGen;
using static Certlib.CertGen;
using Org.BouncyCastle.Crypto;
using RegistrationAuthority.Services;

namespace RegistrationAuthority.Controllers
{
    public class TbsController : Controller
    {
        private readonly TbsService _tbsService;
        public TbsController(TbsService tbsService)
        {
            _tbsService = tbsService;
        }
        public JsonResult GetRsaKeys(int KeySize)
        {
            
            AsymmetricCipherKeyPair Key = GenerateRsaKeyPair(KeySize);
            string Private = KeyWriter(Key.Private);
            string Public = KeyWriter(Key.Public);
            Console.WriteLine(Private);
            Console.WriteLine("****************");
            Console.WriteLine(Public);
            return Json(new { s= Private, h= Public });
        }
        public JsonResult GetEcKeyPair(string CurveName)
        {
            AsymmetricCipherKeyPair Key = GenerateEcKeyPair(CurveName);
            string Private = KeyWriter(Key.Private);
            string Public = KeyWriter(Key.Public);
            Console.WriteLine(Private);
            Console.WriteLine("****************");
            Console.WriteLine(Public);
            return Json(new { s = Private, h = Public });
        }
        public string test(string name)
        {
            //string res = "rafik test";
            //Console.WriteLine(res);
            return name;
        }
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
            TbsModel tbs = new TbsModel();
            return View(tbs);
        }

        // POST: Tbs/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(TbsModel collection)
        {
            try
            {
                // TODO: Add insert logic here
               // Console.WriteLine(collection.Count);
                //foreach (var v in collection) Console.WriteLine(v.Key);
                _tbsService.Create(collection);
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