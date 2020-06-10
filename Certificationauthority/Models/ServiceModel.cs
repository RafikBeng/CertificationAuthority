using Microsoft.AspNetCore.Mvc.Rendering;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Certificationauthority.Models
{
    public class ServiceModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        [Display(Name = "Serial")]
        public Int64 Serial { get; set; }
        [Display(Name = "Password")]
        public string Password { get; set; }
        [Display(Name = "Object")]
        public string Objet { get; set; }
        public List<SelectListItem> Objets { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "Renew", Text = "Renew Certificate" },
            new SelectListItem { Value = "Recover", Text = "Recover Private Key"},
            new SelectListItem { Value = "Revoke", Text = "Revoke Certificate" },
        };
    }
}
