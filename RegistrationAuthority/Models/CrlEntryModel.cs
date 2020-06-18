using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace RegistrationAuthority.Models
{
    public class CrlEntryModel
    {
        [Display(Name = "Serial")]
        public Int64 Serial { get; set; }
        [Display(Name = "Revocation Date")]
        public DateTime RevocationDate { get; set; }
        [Display(Name = "Reason")]
        public string Reason { get; set; }
    }
}
