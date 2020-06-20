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
        public long Serial { get; set; }
        [Display(Name = "Public Key Algorithme")]
        public string Algorithme { get; set; }
        [Display(Name = "Key Size")]
        public int KeySize { get; set; } 
        public string SubjectDN { get; set; }
        public string IssuerDN { get; set; }
        public string Thumbprint { get; set; }
        public string Signature { get; set; }
        public string Extensions { get; set; }
        public bool   IsRootCA { get; set; }
        public DateTime NotAfter { get; set; }
        public DateTime NotBefore { get; set; }
        public string Privatekey { get; set; }
        public string Publickey { get; set; }
        public string Certificat { get; set; }
        [Display(Name = "Password")]
        public string Password { get; set; }
    }
}
