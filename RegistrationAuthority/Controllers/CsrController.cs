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
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto.Operators;
using Microsoft.AspNetCore.Routing;
using Newtonsoft.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Rendering;
using Org.BouncyCastle.Asn1;

namespace RegistrationAuthority.Controllers
{
    
    public class CsrController : Controller
    {
        private readonly CsrService _CsrService;
        public CsrController(CsrService CsrService)
        {
            _CsrService = CsrService;
        }
        public JsonResult GetRsaKeys(int KeySize)
        {
            
            AsymmetricCipherKeyPair Key = GenerateRsaKeyPair(KeySize);
            string Private = KeyWriter(Key.Private);
            string Public = KeyWriter(Key.Public);
            //Console.WriteLine(Private);
            //Console.WriteLine("****************");
            //Console.WriteLine(Public);
            return Json(new { s= Private, h= Public });
        }
        public JsonResult GetEcKeyPair(string CurveName)
        {
            AsymmetricCipherKeyPair Key = GenerateEcKeyPair(CurveName);
            string Private = KeyWriter(Key.Private);
            string Public = KeyWriter(Key.Public);
            //Console.WriteLine(Private);
            //Console.WriteLine("****************");
            //Console.WriteLine(Public);
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
       [HttpGet]
        public ActionResult Details()
        {
            try
            {
                string data = TempData["MyTempData"].ToString();
                string pkcs = TempData["Mypkcs"].ToString();
                
                CsrModel Model = JsonConvert.DeserializeObject<CsrModel>(data);
                byte[] bits = JsonConvert.DeserializeObject<byte[]>(pkcs);
                Pkcs10CertificationRequest pkcs10 = new Pkcs10CertificationRequest(bits);
                Model.Distinguished_Name = pkcs10.GetCertificationRequestInfo().Subject.ToString();
                Model.Certificat = CsrWriter(pkcs10);
                Model.Thumbprint = Convert.ToBase64String(pkcs10.Signature.GetOctets());
                Model.Extensions = ShowExtensions(pkcs10);
                return View(Model);
            }
#pragma warning disable CS0168 // Variable is declared but never used
            catch(NullReferenceException e)
#pragma warning restore CS0168 // Variable is declared but never used
            {
                return RedirectToAction(nameof(Index));
            }

        }

        // GET: Tbs/Create
        public ActionResult Create()
        {
            CsrModel Csr = new CsrModel();
            var contries = _CsrService.GetContries();
            var List_contries = new List<SelectListItem>();
            foreach (var v in contries)
            {
                SelectListItem selectListItem = new SelectListItem(v.ElementAt(0).Value.AsString, v.ElementAt(1).Value.AsString);
                List_contries.Add(selectListItem);
            }
            Csr.Countries = List_contries;
            Csr.CountryName = List_contries.ElementAt(0).Text;
            var states = _CsrService.Getstates(Csr.CountryName);
            Csr.states = states.ToList<SelectListItem>();
            Csr.StateName = states.ElementAt(0).Text;
            var cities = _CsrService.GetCities(Csr.CountryName, Csr.StateName);
            Csr.cities=cities.ToList<SelectListItem>();
            return View(Csr);
        }

        // POST: Tbs/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(CsrModel Csr)
        {
            try
            {
                
                String SubjectDN = $"CN={Csr.CommonName},DC={Csr.DomainComponent},O={Csr.OrganizationName},OU={Csr.OrganizationalUnitName},C={Csr.CountryName},ST={Csr.StateName},L={Csr.City},STREET={Csr.StreetAddress}";
                String[] subjectAlternativeNames = new List<String>().ToArray();
                int[] usage = { 128, 64, 32, 16, 8, 4, 2, 1, 32768 };
                List<int> L = new List<int>();
                if (Csr.DigitalSignature) L.Add(128);
                if (Csr.NonRepudiation) L.Add(64);
                if (Csr.KeyEncipherment) L.Add(32);
                if (Csr.DataEncipherment) L.Add(16);
                if (Csr.KeyAgreement) L.Add(8);
                if (Csr.KeyCertSign) L.Add(4);
                if (Csr.CrlSign) L.Add(2);
                if (Csr.EncipherOnly) L.Add(1);
                if (Csr.DecipherOnly) L.Add(32768);
                
                KeyUsage keyUsage = new KeyUsage(L.Sum());

                List<KeyPurposeID> ExtendUsage = new List<KeyPurposeID>();
                if (Csr.AnyExtendedKeyUsage) ExtendUsage.Add(KeyPurposeID.AnyExtendedKeyUsage);
                if (Csr.IdKPServerAuth) ExtendUsage.Add(KeyPurposeID.IdKPServerAuth);
                if (Csr.IdKPClientAuth) ExtendUsage.Add(KeyPurposeID.IdKPClientAuth);
                if (Csr.IdKPCodeSigning) ExtendUsage.Add(KeyPurposeID.IdKPCodeSigning);
                if (Csr.IdKPEmailProtection) ExtendUsage.Add(KeyPurposeID.IdKPEmailProtection);
                if (Csr.IdKPIpsecEndSystem) ExtendUsage.Add(KeyPurposeID.IdKPIpsecEndSystem);
                if (Csr.IdKPIpsecTunnel) ExtendUsage.Add(KeyPurposeID.IdKPIpsecTunnel);
                if (Csr.IdKPIpsecUser) ExtendUsage.Add(KeyPurposeID.IdKPIpsecUser);
                if (Csr.IdKPTimeStamping) ExtendUsage.Add(KeyPurposeID.IdKPTimeStamping);
                if (Csr.IdKPOcspSigning) ExtendUsage.Add(KeyPurposeID.IdKPOcspSigning);
                if (Csr.IdKPSmartCardLogon) ExtendUsage.Add(KeyPurposeID.IdKPSmartCardLogon);
                if (Csr.IdKPMacAddress) ExtendUsage.Add(KeyPurposeID.IdKPMacAddress);

                AsymmetricCipherKeyPair Key = new AsymmetricCipherKeyPair(PublicKeyReader(Csr.Publickey), PrivateKeyReader(Csr.Privatekey));


                var v = Asn1SignatureFactory.SignatureAlgNames;
                List<string> SignatureAlgNames = new List<string>();
                foreach (var a in v) SignatureAlgNames.Add(a.ToString());
                List<string> tmp = SignatureAlgNames.FindAll(x => x.Contains(Csr.Algorithme));
                tmp.RemoveAll(x => x.Contains("MGF1"));
                string Signature = tmp.Find(x => x.Contains(Csr.Hash));
                
                Csr.Signature = Signature;
               if(Csr.Algorithme == "ECDSA")
                {
                    string resultString = Regex.Match(Csr.Curve, @"\d\d\d+").Value;
                    Csr.KeySize = Int32.Parse(resultString);
                }
                Pkcs10CertificationRequest pkcs10 = CertRequest(new X509Name(SubjectDN), subjectAlternativeNames, Key, Signature, keyUsage, ExtendUsage.ToArray(), false);
                Csr.Certificat= CsrWriter(pkcs10);

                _CsrService.Create(Csr);

                
                string data = JsonConvert.SerializeObject(Csr);
                string pkcs = JsonConvert.SerializeObject(pkcs10.GetDerEncoded());
                TempData.Add("MyTempData", data);
                TempData.Add("Mypkcs", pkcs);
                return RedirectToAction(nameof(Details));
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

        public JsonResult Getstates(string name)
        {
            // string name = "Algeria";
            return Json(_CsrService.Getstates(name));
        }

        public JsonResult GetCities(string country, string state)
        {
            // string name = "Algeria";
            return Json(_CsrService.GetCities(country, state));
        }
    }
}