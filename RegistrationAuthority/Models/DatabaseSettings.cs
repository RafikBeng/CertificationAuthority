using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RegistrationAuthority.Models
{
    public class DatabaseSettings : IDatabaseSettings
    {
        public string Csr { get; set; }
        public string Countries { get; set; }
        public string Services { get; set; }
        public string Cert { get; set; }
        public string Clr { get; set; }
        public string ConnectionString { get; set; }
        public string DatabaseName { get; set; }
    }

    public interface IDatabaseSettings
    {
        string Csr { get; set; }
        string Countries { get; set; }
        string Services { get; set; }
        string Cert { get; set; }
        string Clr { get; set; }
        string ConnectionString { get; set; }
        string DatabaseName { get; set; }
    }
}
