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
    public class CsrModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        // [Required]
        [BsonIgnore]
        [Display(Name = "Common Name")]
        public string CommonName { get; set; }
        public string Password { get; set; }
        [BsonIgnore]
        [Display(Name = "EMAIL")]
        public string MAIL { get; set; }
        [BsonIgnore]
        [Display(Name = "Alternative Names")]
        public string AlternativeNames { get; set; }
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

        //[BsonIgnore]
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
        [BsonIgnore]
        [Display(Name = "Public Key Algorithme")]
        public string Algorithme { get; set; }

        public List<SelectListItem> Algorithmes { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "RSA", Text = "RSA" },
            //new SelectListItem { Value = "DSA", Text = "DSA" },
            new SelectListItem { Value = "ECC", Text = "Elliptic curve"},

        };

        [BsonIgnore]
        [Display(Name = "Key Size")]
        public int KeySize{ get; set; }

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
           
            new SelectListItem { Value = "SHA224", Text = "SHA224" },
            new SelectListItem { Value = "SHA256", Text = "SHA256" },
            new SelectListItem { Value = "SHA384", Text = "SHA384" },
            new SelectListItem { Value = "SHA512", Text = "SHA512" },
            new SelectListItem { Value = "SHA3-224", Text = "SHA3-224" },
            new SelectListItem { Value = "SHA3-256", Text = "SHA3-256" },
            new SelectListItem { Value = "SHA3-384", Text = "SHA3-384" },
            new SelectListItem { Value = "SHA3-512", Text = "SHA3-512" },
        };
        /// <summary>
        //KeyUsage
        /// </summary>
        /// 
        [BsonIgnore]
        public bool DigitalSignature { get; set; }
        [BsonIgnore]
        public bool NonRepudiation { get; set; }
        [BsonIgnore]
        public bool KeyEncipherment { get; set; }
        [BsonIgnore]
        public bool DataEncipherment { get; set; }
        [BsonIgnore]
        public bool KeyAgreement { get; set; }
        [BsonIgnore]
        public bool KeyCertSign { get; set; }
        [BsonIgnore]
        public bool CrlSign { get; set; }
        [BsonIgnore]
        public bool EncipherOnly { get; set; }
        [BsonIgnore]
        public bool DecipherOnly { get; set; }
        /// <summary>
        /// ///////////ExtendedKeyUsage
        /// </summary>
        [BsonIgnore]
        public bool AnyExtendedKeyUsage { get; set; }
        [BsonIgnore]
        public bool IdKPServerAuth { get; set; }
        [BsonIgnore]
        public bool IdKPClientAuth { get; set; }
        [BsonIgnore]
        public bool IdKPCodeSigning { get; set; }
        [BsonIgnore]
        public bool IdKPEmailProtection { get; set; }
        [BsonIgnore]
        public bool IdKPIpsecEndSystem { get; set; }
        [BsonIgnore]
        public bool IdKPIpsecTunnel { get; set; }
        [BsonIgnore]
        public bool IdKPIpsecUser { get; set; }
        [BsonIgnore]
        public bool IdKPTimeStamping { get; set; }
        [BsonIgnore]
        public bool IdKPOcspSigning { get; set; }
        [BsonIgnore]
        public bool IdKPSmartCardLogon { get; set; }
        [BsonIgnore]
        public bool IdKPMacAddress { get; set; }
       
        [BsonIgnore]
        public string Thumbprint { get; set; }
        [BsonIgnore]
        public string Signature { get; set; }
        [BsonIgnore]
        public string Extensions { get; set; }
        public string SubjectDN { get; set; }
        public string Privatekey { get; set; }
        [BsonIgnore]
        public string Publickey { get; set; }
        public string Certificat { get; set; }
    }
}
