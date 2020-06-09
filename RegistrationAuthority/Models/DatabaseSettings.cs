using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RegistrationAuthority.Models
{
    public class DatabaseSettings : IDatabaseSettings
    {
        public string CollectionName { get; set; }
        public string CollectionTwo { get; set; }
        public string CollectionThree { get; set; }
        public string ConnectionString { get; set; }
        public string DatabaseName { get; set; }
    }

    public interface IDatabaseSettings
    {
        string CollectionName { get; set; }
        string CollectionTwo { get; set; }
        string CollectionThree { get; set; }
        string ConnectionString { get; set; }
        string DatabaseName { get; set; }
    }
}
