using Microsoft.AspNetCore.Mvc.Rendering;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace RegistrationAuthority.Models
{
    public class TbsModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
       // [Required]
        [Display(Name = "Common Name")]
        public string CommonName { get; set; }

        [Display(Name = "Domain Component")]
        public string DomainComponent { get; set; }

        [Display(Name = "Organizational Unit")]
        public string OrganizationalUnitName { get; set; }

        [Display(Name = "Country")]
        public string CountryName { get; set; }

        [Display(Name = "State")]
        public string StateName { get; set; }

        [Display(Name = "City")]
        public string City { get; set; }

        [Display(Name = "Street Address")]
        public string StreetAddress { get; set; }

        [Display(Name = "Locality Name")]

        public string LocalityName { get; set; }

        [Display(Name = "Validity")]
        public string Validity { get; set; }

        public List<SelectListItem> Validitys { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "1", Text = "1 Year" },
            new SelectListItem { Value = "2", Text = "2 Years" },
            new SelectListItem { Value = "3", Text = "3 Years"  },
            new SelectListItem { Value = "3", Text = "4 Years"  },
            new SelectListItem { Value = "3", Text = "5 Years"  },
        };

        [Display(Name = "Public Key Algorithme")]
        public string Algorithme { get; set; }

        public List<SelectListItem> Algorithmes { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "RSA", Text = "RSA" },
            new SelectListItem { Value = "DSA", Text = "DSA" },
            new SelectListItem { Value = "EC", Text = "Elliptic curve"},

        };

        [Display(Name = "Key Size")]
        public int KeySize{ get; set; } = 1024;

        [Display(Name = "EC Type")]
        public string ECType { get; set; }
        public List<SelectListItem> ECTypes { get; } = new List<SelectListItem>
        {
              new SelectListItem { Value = "X962NamedCurves", Text = "X962 Curves" },
              new SelectListItem { Value = "SecNamedCurves", Text = "Sec Curves" },
              new SelectListItem { Value = "NistNamedCurves", Text = "Nist Curves" },
              new SelectListItem { Value = "TeleTrusTNamedCurves", Text = "TeleTrusT Curves" },
          //  new SelectListItem { Value = "B-163", Text = "B 163-bit binary field Weierstrass curve" },
          //  new SelectListItem { Value = "B-233", Text = "B 233-bit binary field Weierstrass curve" },
          //  new SelectListItem { Value = "B-283", Text = "B 283-bit binary field Weierstrass curve" },
          //  new SelectListItem { Value = "B-409", Text = "B 409-bit binary field Weierstrass curve" },
          //  new SelectListItem { Value = "B-571", Text = "B 571-bit binary field Weierstrass curve" },
          //  new SelectListItem { Value = "FRP256v1", Text ="FRPV1 256-bit prime field Weierstrass curve" },
          ////  new SelectListItem { Value = "GostR3410", Text = "GostR3410" },
          //  new SelectListItem { Value = "K-163", Text = "K 163-bit binary field Weierstrass curve" },
          //  new SelectListItem { Value = "K-233", Text = "K 233-bit binary field Weierstrass curve" },
          //  new SelectListItem { Value = "K-283", Text = "K 283-bit binary field Weierstrass curve" },
          //  new SelectListItem { Value = "K-409", Text = "K 409-bit binary field Weierstrass curve"},
          //  new SelectListItem { Value = "K-571", Text = "K 571-bit binary field Weierstrass curve" },
          //  new SelectListItem { Value = "P-192", Text = "P 192-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "P-224", Text = "P 224-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "P-256", Text = "P 256-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "P-384", Text = "P 384-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "P-521", Text = "P 521-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP160r1", Text = "brainpoolr1 160-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP160t1", Text = "brainpoolt1 160-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP192r1", Text = "brainpoolr1 192-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP192t1", Text = "brainpoolt1 192-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP224r1", Text = "brainpoolr1 224-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP224t1", Text = "brainpoolt1 224-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP256r1", Text = "brainpoolr1 256-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP256t1", Text = "brainpoolt1 256-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP320r1", Text = "brainpoolr1 320-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP320t1", Text = "brainpoolt1 320-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP384r1", Text = "brainpoolr1 384-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP512t1", Text = "brainpoolt1 384-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP512r1", Text = "brainpoolr1 512-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "brainpoolP512t1", Text = "brainpoolt1 512-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "prime192v2", Text = "Prime V2-192-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "prime192v3", Text = "Prime V3-192-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "prime239v1", Text = "Prime V1-239-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "prime239v2", Text = "Prime V2-239-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "prime239v3", Text = "Prime V3-239-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp112r1", Text = "secpr1 112-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp112r2", Text = "secpr2 112-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp128r1", Text = "secpr1 128-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp128r2", Text = "secpr2 128-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp112r1", Text = "secpr1 112-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp112r2", Text = "secpr2 112-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp160k1", Text = "secpk1 160-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp160r1", Text = "secpr1 160-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp160r2", Text = "secpr2 160-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp192k1", Text = "secpk1 192-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp224k1", Text = "secpk1 224-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "secp256k1", Text = "secpk1 256-bit prime field Weierstrass curve" },
          //  new SelectListItem { Value = "sect113r1", Text = "sectr1 113-bit binary field Weierstrass curve." },
          //  new SelectListItem { Value = "sect113r2", Text = "sectr2 113-bit binary field Weierstrass curve." },
          //  new SelectListItem { Value = "sect131r1", Text = "sectr1 131-bit binary field Weierstrass curve." },
          //  new SelectListItem { Value = "sect131r2", Text = "sectr2 131-bit binary field Weierstrass curve." },
          //  new SelectListItem { Value = "sect163r1", Text = "sectr1 163-bit binary field Weierstrass curve." },
          //  new SelectListItem { Value = "sect193r1", Text = "sectr1 193-bit binary field Weierstrass curve." },
          //  new SelectListItem { Value = "sect193r2", Text = "sectr2 193-bit binary field Weierstrass curve." },
          //  new SelectListItem { Value = "sect239k1", Text = "sectk1 239-bit binary field Weierstrass curve." },

        };
        [Display(Name = "Curve")]
        public string Curve { get; set; }

        [Display(Name = "Hash")]
        public string Hash { get; set; } 
        
        public List<SelectListItem> Hashs { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "MD2", Text = "MD2" },
            new SelectListItem { Value = "MD5", Text = "MD5" },
            new SelectListItem { Value = "SHA1", Text = "SHA1" },
            new SelectListItem { Value = "SHA224", Text = "SHA224" },
            new SelectListItem { Value = "SHA224", Text = "SHA224" },
            new SelectListItem { Value = "SHA256", Text = "SHA256" },
            new SelectListItem { Value = "SHA384", Text = "SHA384" },
            new SelectListItem { Value = "SHA384", Text = "SHA384" },
            new SelectListItem { Value = "SHA512", Text = "SHA512" },
            new SelectListItem { Value = "RIPEMD160", Text = "RIPEMD160" },
            new SelectListItem { Value = "RIPEMD128", Text = "RIPEMD128" },
            new SelectListItem { Value = "RIPEMD256", Text = "RIPEMD256" },
        };

        public string Privatekey { get; set; }

        public byte[] RawData { get; set; }
    }
}
