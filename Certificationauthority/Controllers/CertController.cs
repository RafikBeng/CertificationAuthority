using System;
using System.Collections.Generic;
using System.Linq;
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
using Newtonsoft.Json;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace Certificationauthority.Controllers
{
    public class CertController : Controller
    {
        private readonly CertService _CertService;
        public CertController(CertService CertService)
        {
            _CertService = CertService;
        }
        public FileContentResult Download(long Serial)
        {
            CertModel result = _CertService.GetCert(Serial);
            X509Certificate Certificate = new X509CertificateParser().ReadCertificate(CertReader(result.Certificat));
            string name = Certificate.SubjectDN.GetValueList(X509Name.CN)[0].ToString();
            string path = name + "-" + result.Serial.ToString() + ".cer";

            return File(Certificate.GetEncoded(), "Certificate/cer", path);
        }
        public FileContentResult Download_PEM(long Serial)
        {
            CertModel result = _CertService.GetCert(Serial);
            X509Certificate Certificate = new X509CertificateParser().ReadCertificate(CertReader(result.Certificat));
            string name = Certificate.SubjectDN.GetValueList(X509Name.CN)[0].ToString();
            string path = name + "-" + result.Serial.ToString() + ".pem";

            return File(Encoding.UTF8.GetBytes(result.Certificat), "Certificate/pem", path);
        }
        public FileContentResult Download_PEM_Public(long Serial)
        {
            CertModel result = _CertService.GetCert(Serial);
            X509Certificate Certificate = new X509CertificateParser().ReadCertificate(CertReader(result.Certificat));
            string name = Certificate.SubjectDN.GetValueList(X509Name.CN)[0].ToString();
            string path = name + "-" + result.Serial.ToString() + "-Public-Key" + ".pem";
            string Public = KeyWriter(Certificate.GetPublicKey());
            return File(Encoding.UTF8.GetBytes(Public), "key/pem", path);
        }
        public FileContentResult Download_PEM_Private(long Serial)
        {
            CertModel result = _CertService.GetCert(Serial);
            X509Certificate Certificate = new X509CertificateParser().ReadCertificate(CertReader(result.Certificat));
            string name = Certificate.SubjectDN.GetValueList(X509Name.CN)[0].ToString();
            string path = name + "-" + result.Serial.ToString() + "-Private-Key" + ".pem";
            string Public = result.Privatekey;
            return File(Encoding.UTF8.GetBytes(Public), "key/pem", path);
        }
        public JsonResult GetRsaKeys(int KeySize)
        {

            AsymmetricCipherKeyPair Key = GenerateRsaKeyPair(KeySize);
            string Private = KeyWriter(Key.Private);
            string Public = KeyWriter(Key.Public);
           
            return Json(new { s = Private, h = Public });
        }

        public JsonResult GetEcKeyPair(string CurveName)
        {
            AsymmetricCipherKeyPair Key = GenerateEcKeyPair(CurveName);
            string Private = KeyWriter(Key.Private);
            string Public = KeyWriter(Key.Public);
           
            return Json(new { s = Private, h = Public });
        }

        public ActionResult List()
        {
            return View(_CertService.GetCerts());
        }
        // GET: Cert
        public ActionResult Index()
        {
            CertModel cert = _CertService.GetCert(true);
            if(cert==null) return RedirectToAction(nameof(Create));
            else return RedirectToAction("Detail", new { Serial = cert.Serial });

        }
        public ActionResult Detail(long Serial)
        {
            CertModel result = _CertService.GetCert(Serial);
            X509Certificate Certificate= new X509CertificateParser().ReadCertificate(CertReader(result.Certificat));
            CertModel Model = new CertModel
            {
                SubjectDN = Certificate.SubjectDN.ToString(),
                IssuerDN= Certificate.IssuerDN.ToString(),
                Thumbprint = Hex.ToHexString(Certificate.GetSignature()),
                Extensions = ShowExtensions(Certificate),
                Publickey = KeyWriter(Certificate.GetPublicKey()),
                Privatekey = result.Privatekey,
                Signature = Certificate.SigAlgName,
                Serial = Serial,
                Validity = result.Validity,
                Certificat = result.Certificat,
              
                NotAfter=Certificate.NotAfter,
                NotBefore=Certificate.NotBefore
            };
            AsymmetricKeyParameter key = Certificate.GetPublicKey();
            if (Certificate.SigAlgName.Contains("RSA"))
            {
                Model.Algorithme = "RSA";
                RsaKeyParameters rsaKey = (RsaKeyParameters)key;
                Model.KeySize = rsaKey.Modulus.BitLength;
            }
            else
            {
                Model.Algorithme = "ECC";
                ECPublicKeyParameters publicKeyParam = (ECPublicKeyParameters)key;
                Model.KeySize = publicKeyParam.Parameters.Curve.FieldSize;
            }
            return View("Details",Model);

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
               // Model.SubjectDN = certificate.SubjectDN.ToString();
               // Model.IssuerDN = Model.SubjectDN;
                Model.Certificat = CertWriter(certificate);
                Model.Thumbprint = Hex.ToHexString(certificate.GetSignature());
                Model.Extensions = ShowExtensions(certificate);
                return View(Model);
            }

            catch (Exception e)

            {
                return View("Error",e);
               
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
           
                String SubjectDN = $"CN={Cert.CommonName},O={Cert.OrganizationName},OU={Cert.OrganizationalUnitName},C={Cert.CountryName},ST={Cert.StateName},L={Cert.City},STREET={Cert.StreetAddress},E={Cert.MAIL}";
                String[] subjectAlternativeNames = new List<String>().ToArray();

                List<int> L = new List<int>
                {
                    128,
                    64,
                    32,
                    16,
                    8,
                    4,
                    2,
                    1,
                    32768
                };

                KeyUsage keyUsage = new KeyUsage(L.Sum());

                List<KeyPurposeID> ExtendUsage = new List<KeyPurposeID>
                {
                    KeyPurposeID.AnyExtendedKeyUsage,
                    KeyPurposeID.IdKPServerAuth,
                    KeyPurposeID.IdKPClientAuth,
                    KeyPurposeID.IdKPCodeSigning,
                    KeyPurposeID.IdKPEmailProtection,
                    KeyPurposeID.IdKPIpsecEndSystem,
                    KeyPurposeID.IdKPIpsecTunnel,
                    KeyPurposeID.IdKPIpsecUser,
                    KeyPurposeID.IdKPTimeStamping,
                    KeyPurposeID.IdKPOcspSigning,
                    KeyPurposeID.IdKPSmartCardLogon,
                    KeyPurposeID.IdKPMacAddress
                };

                AsymmetricCipherKeyPair Key = new AsymmetricCipherKeyPair(PublicKeyReader(Cert.Publickey), PrivateKeyReader(Cert.Privatekey));


                var v = Asn1SignatureFactory.SignatureAlgNames;
                List<string> SignatureAlgNames = new List<string>();
                foreach (var a in v) SignatureAlgNames.Add(a.ToString());
                if (Cert.Algorithme == "RSA")
                {
                    List<string> tmp = SignatureAlgNames.FindAll(x => x.Contains(Cert.Algorithme));
                    tmp.RemoveAll(x => x.Contains("MGF1"));
                    string Signature = tmp.Find(x => x.Contains(Cert.Hash));
                    Cert.Signature = Signature;
                }
                else
                {
                    List<string> tmp = SignatureAlgNames.FindAll(x => x.Contains("ECDSA"));
                    tmp.RemoveAll(x => x.Contains("MGF1"));
                    string Signature = tmp.Find(x => x.Contains(Cert.Hash));
                    Cert.Signature = Signature;
                    string resultString = Regex.Match(Cert.Curve, @"\d\d\d+").Value;
                    Cert.KeySize = Int32.Parse(resultString);
                }


                SecureRandom random = new SecureRandom();
                // BigInteger Serial = GenerateSerialNumber(random);
                BigInteger Serial = BigInteger.One;
                Cert.Serial = Int64.Parse(Serial.ToString());
                X509Certificate certificate = RootCA(Serial, Key, SubjectDN, subjectAlternativeNames, keyUsage, ExtendUsage.ToArray(), Cert.Signature, int.Parse(Cert.Validity));
                Cert.Certificat = CertWriter(certificate);
                Cert.IsRootCA = true;
                Cert.NotAfter = certificate.NotAfter;
                Cert.NotBefore = certificate.NotBefore;
                Cert.SubjectDN = certificate.SubjectDN.ToString();
                Cert.IssuerDN = certificate.IssuerDN.ToString();
                _CertService.Create(Cert);
                string data = JsonConvert.SerializeObject(Cert);
                string Root = JsonConvert.SerializeObject(certificate.GetEncoded());
                TempData.Add("MyTempData", data);
                TempData.Add("MyRoot", Root);
                return RedirectToAction(nameof(Details));
       
          
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

        public JsonResult Getstates(string name)
        {
            
            return Json(_CertService.Getstates(name));
        }

        public JsonResult GetCities(string country, string state)
        {
            
            return Json(_CertService.GetCities(country, state));
        }
    }
}