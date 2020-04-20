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
        [BsonIgnore]
        [Display(Name = "Common Name")]
        public string CommonName { get; set; }

        [BsonIgnore]
        [Display(Name = "Domain Component")]
        public string DomainComponent { get; set; }
    
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
        [Display(Name = "State")]
        public string StateName { get; set; }

        [BsonIgnore]
        [Display(Name = "City")]
        public string City { get; set; }

        [BsonIgnore]
        [Display(Name = "Street Address")]
        public string StreetAddress { get; set; }

        [BsonIgnore]
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
            new SelectListItem { Value = "EC", Text = "Elliptic curve"},

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
        /// <summary>
        //KeyUsage
        /// </summary>
        /// 
        [BsonIgnore]
        public bool DigitalSignature ;
        public bool NonRepudiation ;
        [BsonIgnore]
        public bool KeyEncipherment ;
        [BsonIgnore]
        public bool DataEncipherment ;
        [BsonIgnore]
        public bool KeyAgreement ;
        [BsonIgnore]
        public bool KeyCertSign ;
        [BsonIgnore]
        public bool CrlSign ;
        [BsonIgnore]
        public bool EncipherOnly;
        [BsonIgnore]
        public bool DecipherOnly ;
        /// <summary>
        /// ///////////ExtendedKeyUsage
        /// </summary>
        [BsonIgnore]
        public bool AnyExtendedKeyUsage;
        [BsonIgnore]
        public bool IdKPServerAuth;
        [BsonIgnore]
        public bool IdKPClientAuth;
        [BsonIgnore]
        public bool IdKPCodeSigning;
        [BsonIgnore]
        public bool IdKPEmailProtection;
        [BsonIgnore]
        public bool IdKPIpsecEndSystem;
        [BsonIgnore]
        public bool IdKPIpsecTunnel;
        [BsonIgnore]
        public bool IdKPIpsecUser;
        [BsonIgnore]
        public bool IdKPTimeStamping;
        [BsonIgnore]
        public bool IdKPOcspSigning;
        [BsonIgnore]
        public bool IdKPSmartCardLogon;
        [BsonIgnore]
        public bool IdKPMacAddress;


        public string Privatekey { get; set; }
        public string Publickey { get; set; }
        public byte[] RawData { get; set; }
    }
}
