using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certificationauthority.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto;
using static Certlib.KeyGen;
using static Certlib.CertGen;
using Certificationauthority.Models;
using Microsoft.AspNetCore.Mvc.Rendering;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Pkcs;
using Newtonsoft.Json;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Certificationauthority.Controllers
{
    public class CertController : Controller
    {
        private readonly CertService _CertService;
        public CertController(CertService CertService)
        {
            _CertService = CertService;
        }

        public JsonResult GetRsaKeys(int KeySize)
        {

            AsymmetricCipherKeyPair Key = GenerateRsaKeyPair(KeySize);
            string Private = KeyWriter(Key.Private);
            string Public = KeyWriter(Key.Public);
            //Console.WriteLine(Private);
            //Console.WriteLine("****************");
            //Console.WriteLine(Public);
            return Json(new { s = Private, h = Public });
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
        // GET: Cert
        public ActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public ActionResult Details()
        {
            try
            {
                string data = TempData["MyTempData"].ToString();
                string Root = TempData["MyRoot"].ToString();
                CertModel Model = JsonConvert.DeserializeObject<CertModel>(data);
                byte[] bits = JsonConvert.DeserializeObject<byte[]>(Root);
                X509Certificate certificate = new X509CertificateParser().ReadCertificate(bits);
                Model.Distinguished_Name = certificate.SubjectDN.ToString();
                Model.Certificat = CertWriter(certificate);
                Model.Thumbprint = Convert.ToBase64String(certificate.GetSignature());
                Model.Extensions = ShowExtensions(certificate);
                return View(Model);
            }
#pragma warning disable CS0168 // Variable is declared but never used
            catch (NullReferenceException e)
#pragma warning restore CS0168 // Variable is declared but never used
            {
                return RedirectToAction(nameof(Index));
            }
        }

        // GET: Cert/Create
        public ActionResult Create()
        {
            CertModel Cert = new CertModel();
            var contries = _CertService.GetContries();
            var List_contries = new List<SelectListItem>();
            foreach (var v in contries)
            {
                SelectListItem selectListItem = new SelectListItem(v.ElementAt(0).Value.AsString, v.ElementAt(1).Value.AsString);
                List_contries.Add(selectListItem);
            }
            Cert.Countries = List_contries;
            Cert.CountryName = List_contries.ElementAt(0).Text;
            var states = _CertService.Getstates(Cert.CountryName);
            Cert.states = states.ToList<SelectListItem>();
            Cert.StateName = states.ElementAt(0).Text;
            var cities = _CertService.GetCities(Cert.CountryName, Cert.StateName);
            Cert.cities = cities.ToList<SelectListItem>();
            return View(Cert);
        }

        // POST: Cert/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(CertModel Cert)
        {
            try
            {
                String SubjectDN = $"CN={Cert.CommonName},DC={Cert.DomainComponent},O={Cert.OrganizationName},OU={Cert.OrganizationalUnitName},C={Cert.CountryName},ST={Cert.StateName},L={Cert.City},STREET={Cert.StreetAddress}";
                String[] subjectAlternativeNames = new List<String>().ToArray();
                
                List<int> L = new List<int>();
                if (Cert.DigitalSignature) L.Add(128);
                if (Cert.NonRepudiation) L.Add(64);
                if (Cert.KeyEncipherment) L.Add(32);
                if (Cert.DataEncipherment) L.Add(16);
                if (Cert.KeyAgreement) L.Add(8);
                if (Cert.KeyCertSign) L.Add(4);
                if (Cert.CrlSign) L.Add(2);
                if (Cert.EncipherOnly) L.Add(1);
                if (Cert.DecipherOnly) L.Add(32768);

                KeyUsage keyUsage = new KeyUsage(L.Sum());

                List<KeyPurposeID> ExtendUsage = new List<KeyPurposeID>();
                if (Cert.AnyExtendedKeyUsage) ExtendUsage.Add(KeyPurposeID.AnyExtendedKeyUsage);
                if (Cert.IdKPServerAuth) ExtendUsage.Add(KeyPurposeID.IdKPServerAuth);
                if (Cert.IdKPClientAuth) ExtendUsage.Add(KeyPurposeID.IdKPClientAuth);
                if (Cert.IdKPCodeSigning) ExtendUsage.Add(KeyPurposeID.IdKPCodeSigning);
                if (Cert.IdKPEmailProtection) ExtendUsage.Add(KeyPurposeID.IdKPEmailProtection);
                if (Cert.IdKPIpsecEndSystem) ExtendUsage.Add(KeyPurposeID.IdKPIpsecEndSystem);
                if (Cert.IdKPIpsecTunnel) ExtendUsage.Add(KeyPurposeID.IdKPIpsecTunnel);
                if (Cert.IdKPIpsecUser) ExtendUsage.Add(KeyPurposeID.IdKPIpsecUser);
                if (Cert.IdKPTimeStamping) ExtendUsage.Add(KeyPurposeID.IdKPTimeStamping);
                if (Cert.IdKPOcspSigning) ExtendUsage.Add(KeyPurposeID.IdKPOcspSigning);
                if (Cert.IdKPSmartCardLogon) ExtendUsage.Add(KeyPurposeID.IdKPSmartCardLogon);
                if (Cert.IdKPMacAddress) ExtendUsage.Add(KeyPurposeID.IdKPMacAddress);

                AsymmetricCipherKeyPair Key = new AsymmetricCipherKeyPair(PublicKeyReader(Cert.Publickey), PrivateKeyReader(Cert.Privatekey));


                var v = Asn1SignatureFactory.SignatureAlgNames;
                List<string> SignatureAlgNames = new List<string>();
                foreach (var a in v) SignatureAlgNames.Add(a.ToString());
                List<string> tmp = SignatureAlgNames.FindAll(x => x.Contains(Cert.Algorithme));
                tmp.RemoveAll(x => x.Contains("MGF1"));
                string Signature = tmp.Find(x => x.Contains(Cert.Hash));

                Cert.Signature = Signature;
                if (Cert.Algorithme == "ECDSA")
                {
                    string resultString = Regex.Match(Cert.Curve, @"\d\d\d+").Value;
                    Cert.KeySize = Int32.Parse(resultString);
                }
               
                
                SecureRandom random = new SecureRandom();
                BigInteger Serial = GenerateSerialNumber(random);

                X509Certificate certificate = RootCA(Serial, Key, SubjectDN, subjectAlternativeNames, keyUsage, ExtendUsage.ToArray(), Signature, int.Parse(Cert.Validity));
                Cert.Certificat = CertWriter(certificate);
                _CertService.Create(Cert);


                string data = JsonConvert.SerializeObject(Cert);
                string Root = JsonConvert.SerializeObject(certificate.GetEncoded());
                TempData.Add("MyTempData", data);
                TempData.Add("MyRoot", Root);
                return RedirectToAction(nameof(Details));
            }
            catch
            {
                return View();
            }
        }

        // GET: Cert/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: Cert/Edit/5
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

        // GET: Cert/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: Cert/Delete/5
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