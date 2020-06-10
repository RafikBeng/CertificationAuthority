using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Certificationauthority.Models
{
    public class CsrModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        [Display(Name = "Validity")]
        public string Validity { get; set; }
        [Display(Name = "Subject DN")]
        public string SubjectDN { get; set; }
        [Display(Name = "Private key")]
        public string Privatekey { get; set; }
        [Display(Name = "Public key")]
        public string Publickey { get; set; }
        [Display(Name = "Certificat")]
        public string Certificat { get; set; }
        [Display(Name = "Password")]
        public string Password { get; set; }

    }
}
