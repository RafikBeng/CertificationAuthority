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
    public class CertModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        // [Required]
        public Int64 Serial { get; set; }
        [BsonIgnore]
        [Display(Name = "Common Name")]
        public string CommonName { get; set; }
        [BsonIgnore]
        [Display(Name = "EMAIL")]
        public string MAIL { get; set; }
       
        [BsonIgnore]
        [Display(Name = "Organization")]
        public string OrganizationName { get; set; }
        [BsonIgnore]
        [Display(Name = "Organizational Unit")]
        public string OrganizationalUnitName { get; set; }

        [BsonIgnore]
        [Display(Name = "Country")]
        public string CountryName { get; set; }
        [BsonIgnore]
        public List<SelectListItem> Countries { get; set; } = new List<SelectListItem>();
        [BsonIgnore]
        [Display(Name = "State")]
        public string StateName { get; set; }
        [BsonIgnore]
        public List<SelectListItem> states { get; set; } = new List<SelectListItem>();
        [BsonIgnore]
        [Display(Name = "City")]
        public string City { get; set; }
        [BsonIgnore]
        public List<SelectListItem> cities { get; set; } = new List<SelectListItem>();
        [BsonIgnore]
        [Display(Name = "Street Address")]
        public string StreetAddress { get; set; }

        [BsonIgnore]
        [Display(Name = "Validity")]
        public string Validity { get; set; }

        public List<SelectListItem> Validitys { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "5", Text = "5 Years" },
            new SelectListItem { Value = "10", Text = "10 Years" },
            new SelectListItem { Value = "15", Text = "15 Years"  },
            new SelectListItem { Value = "20", Text = "20 Years"  },
            
        };
        [BsonIgnore]
        [Display(Name = "Public Key Algorithme")]
        public string Algorithme { get; set; }

        public List<SelectListItem> Algorithmes { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "RSA", Text = "RSA" },
            //new SelectListItem { Value = "DSA", Text = "DSA" },
            new SelectListItem { Value = "ECDSA", Text = "Elliptic curve"},

        };

        [BsonIgnore]
        [Display(Name = "Key Size")]
        public int KeySize { get; set; }

        [BsonIgnore]
        [Display(Name = "EC Type")]
        public string ECType { get; set; }
        public List<SelectListItem> ECTypes { get; } = new List<SelectListItem>
        {
              new SelectListItem { Value = "X962NamedCurves", Text = "X962 Curves" },
              new SelectListItem { Value = "SecNamedCurves", Text = "Sec Curves" },
              new SelectListItem { Value = "NistNamedCurves", Text = "Nist Curves" },
              new SelectListItem { Value = "TeleTrusTNamedCurves", Text = "TeleTrusT Curves" },


        };
        [BsonIgnore]
        [Display(Name = "Curve")]
        public string Curve { get; set; }

        [BsonIgnore]
        [Display(Name = "Hash")]
        public string Hash { get; set; }

        public List<SelectListItem> Hashs { get; } = new List<SelectListItem>
        {
            //new SelectListItem { Value = "MD2", Text = "MD2" },
            //new SelectListItem { Value = "MD5", Text = "MD5" },
            //new SelectListItem { Value = "SHA1", Text = "SHA1" },
            new SelectListItem { Value = "SHA224", Text = "SHA224" },
            new SelectListItem { Value = "SHA256", Text = "SHA256" },
            new SelectListItem { Value = "SHA384", Text = "SHA384" },
            new SelectListItem { Value = "SHA384", Text = "SHA384" },
            new SelectListItem { Value = "SHA512", Text = "SHA512" },
            //new SelectListItem { Value = "RIPEMD160", Text = "RIPEMD160" },
            //new SelectListItem { Value = "RIPEMD128", Text = "RIPEMD128" },
            //new SelectListItem { Value = "RIPEMD256", Text = "RIPEMD256" },
        };
       
       // [BsonIgnore]
        public string SubjectDN { get; set; }
        [BsonIgnore]
        public string IssuerDN { get; set; }
        [BsonIgnore]
        public string Thumbprint { get; set; }
        [BsonIgnore]
        public string Signature { get; set; }
        [BsonIgnore]
        public string Extensions { get; set; }
        public bool   IsRootCA { get; set; }
        public DateTime NotAfter { get; set; }
        public DateTime NotBefore { get; set; }
        public string Privatekey { get; set; }
        [BsonIgnore]
        public string Publickey { get; set; }
        public string Certificat { get; set; }
        [Display(Name = "Password")]
        public string Password { get; set; }
    }
}
