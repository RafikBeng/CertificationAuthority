using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certificationauthority.Models
{
    public class DatabaseSettings : IDatabaseSettings
    {
        public string Collection { get; set; }
        public string Countries { get; set; }
        public string Csr { get; set; }
        public string ConnectionString { get; set; }
        public string DatabaseName { get; set; }
    }

    public interface IDatabaseSettings
    {
        string Collection { get; set; }
        string Countries { get; set; }
        string Csr { get; set; }
        string ConnectionString { get; set; }
        string DatabaseName { get; set; }
    }
}
