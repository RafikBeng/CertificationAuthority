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
        public string Object { get; set; }
        public List<SelectListItem> Objects { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "Renew", Text = "Renew Certificate" },
            new SelectListItem { Value = "Recover", Text = "Recover Private Key"},
            new SelectListItem { Value = "Revoke", Text = "Revoke Certificate" },
        };
        [Display(Name = "Reason")]
        public string Reason { get; set; }
        public List<SelectListItem> Reasons { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "0", Text = "unspecified" },
            new SelectListItem { Value = "1", Text = "key Compromise"},
            new SelectListItem { Value = "3", Text = "Affiliation Changed" },
            new SelectListItem { Value = "4", Text = "superseded" },
            new SelectListItem { Value = "5", Text = "Cessation Of Operation"},
            new SelectListItem { Value = "6", Text = "Certificate Hold" },
            new SelectListItem { Value = "9", Text = "Privilege With drawn"}
           
        };

    }
}
