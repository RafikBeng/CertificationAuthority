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
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: Tbs/Create
        public ActionResult Create()
        {
            CsrModel Csr = new CsrModel();
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
                string Signature = tmp.Find(x => x.Contains(Csr.Hash));
                //Console.WriteLine(Signature);
                Pkcs10CertificationRequest pkcs10 = CertRequest(new X509Name(SubjectDN), subjectAlternativeNames, Key, Signature, keyUsage, ExtendUsage.ToArray(), false);
                Csr.RawData = pkcs10.GetDerEncoded();
                _CsrService.Create(Csr);
                
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