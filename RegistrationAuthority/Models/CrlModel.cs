using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace RegistrationAuthority.Models
{
    public class CrlModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        // [Required]
        [Display(Name = "Serial")]
        public Int64 Serial { get; set; }
        [Display(Name = "Issuer DN")]
        public string DN { get; set; }
        [Display(Name = "ThisUpdate")]
        public DateTime ThisUpdate { get; set; }
        [Display(Name = "NextUpdate")]
        public DateTime NextUpdate { get; set; }
        [Display(Name = "Content")]
        public string Content { get; set; }
        [BsonIgnore]
        public List<CrlEntryModel> RevokedCertificates { get; set; }
    }
}
