using Microsoft.AspNetCore.Http;
using MongoDB.Driver;
using RegistrationAuthority.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RegistrationAuthority.Services
{
    public class TbsService
    {
        private readonly IMongoCollection<TbsModel> _TbsModel;
        public TbsService(IDatabaseSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);
            _TbsModel = database.GetCollection<TbsModel>(settings.CollectionName);
        }

        public void Create(TbsModel collection)
        {
            _TbsModel.InsertOne(collection);
        }
    }
}
