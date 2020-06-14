using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certificationauthority.Models
{
    public class CrlModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        // [Required]
        public Int64 Serial { get; set; }
        public DateTime ThisUpdate { get; set; }
        public DateTime NextUpdate { get; set; }
        public string Content { get; set; }
        public string Reason { get; set; }
    }
}
