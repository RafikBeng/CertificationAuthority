using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RegistrationAuthority.Models
{
    public class ContryModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        [BsonElement("_id")]
        public string _id { get; set; }
        [BsonElement("name")]
        public string Name { get; set; }
        [BsonElement("iso2")]
        public string Iso2 { get; set; }
        [BsonElement("states")]
        public List<List<string>> States { get; set; }
    }
}
