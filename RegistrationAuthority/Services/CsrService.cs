using Microsoft.AspNetCore.Http;
using MongoDB.Driver;
using RegistrationAuthority.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RegistrationAuthority.Services
{
    public class CsrService
    {
        private readonly IMongoCollection<CsrModel> _CsrModel;
        public CsrService(IDatabaseSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);
            _CsrModel = database.GetCollection<CsrModel>(settings.CollectionName);
        }

        public void Create(CsrModel collection)
        {
            _CsrModel.InsertOne(collection);
        }
    }
}
