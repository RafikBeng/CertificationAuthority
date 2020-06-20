using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
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
            ServiceModel model = new ServiceModel();
            return View("Index",model);
            
        }

        // GET: Service/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: Service/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Service/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(ServiceModel collection)
        {
            //try
            //{
                var cert = _CsrService.GetCert(collection.Serial);
                
                if(cert==null)
                {
                    ViewBag.Message = "The Certificate does not existe.";
                    return View("Error");
                }
                else
                {
                    string Digest= GetHash(collection.Password);
                    if(Digest!=cert.Password)
                    {
                        ViewBag.Message = "The Password is Incorrect.";
                        return View("Error");
                    }
                    else
                    {
                        collection.Password = Digest;
                        _CsrService.Create(collection);
                        ViewBag.Message = "Your Request Has Been Sended.";
                        return View("Succes");
                    }

                }   
            //}
            //catch (Exception e)
            //{
            //    ViewBag.Message = e.Message;
            //    return View("Error");
            //}
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