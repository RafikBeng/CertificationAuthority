using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Rendering;
using MongoDB.Bson;
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
        private readonly IMongoCollection<BsonDocument> _Contries;
        public CsrService(IDatabaseSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);
            _CsrModel = database.GetCollection<CsrModel>(settings.CollectionName);
            _Contries = database.GetCollection<BsonDocument>(settings.CollectionTwo);
        }

        public void Create(CsrModel collection)
        {
            _CsrModel.InsertOne(collection);
        }

        public List<BsonDocument> GetContries()
        {
            string[] fieldsToReturn = new[] { "name", "iso2" };
            FilterDefinition<BsonDocument> filter = Builders<BsonDocument>.Filter.Empty;
            //ProjectionDefinition<BsonDocument> projection = Builders<BsonDocument>.Projection.Include("name").Exclude("_id");
            // projection.Include("iso2");
            var projectionBuilder = Builders<BsonDocument>.Projection;
            var projection = projectionBuilder.Combine(fieldsToReturn.Select(field => projectionBuilder.Include(field).Exclude("_id")));
            var result = _Contries.Find<BsonDocument>(filter).Project(projection).ToList();
            return result;
        }

        public IEnumerable<SelectListItem> Getstates(string name)
        {

            FilterDefinition<BsonDocument> filter = Builders<BsonDocument>.Filter.Eq("name", name);
            ProjectionDefinition<BsonDocument> projection = Builders<BsonDocument>.Projection.Include("states").Exclude("_id");
            var result = _Contries.Find<BsonDocument>(filter).Project(projection).ToList();
            BsonDocument bson = result.ElementAt(0);
            BsonDocument bson1 = bson.ElementAt(0).Value.AsBsonDocument;
            
            var tmp1 = new List<SelectListItem>();
            foreach (var v in bson1)
            {
                Console.WriteLine(v.Name);
                SelectListItem selectListItem = new SelectListItem(v.Name, v.Name);
                tmp1.Add(selectListItem);
            }
            return tmp1;

        }
        public IEnumerable<SelectListItem> GetCities(string country,string state)
        {

            FilterDefinition<BsonDocument> filter = Builders<BsonDocument>.Filter.Eq("name", country);
            ProjectionDefinition<BsonDocument> projection = Builders<BsonDocument>.Projection.Include("states").Exclude("_id");
            var result = _Contries.Find<BsonDocument>(filter).Project(projection).ToList();
            BsonDocument bson = result.ElementAt(0);
            BsonDocument bson1 = bson.ElementAt(0).Value.AsBsonDocument;
            BsonArray bson2 = bson1.GetElement(state).Value.AsBsonArray;
           
            var tmp1 = new List<SelectListItem>();
            foreach (var v in bson2)
            {
                
                SelectListItem selectListItem = new SelectListItem(v.AsString, v.AsString);
                tmp1.Add(selectListItem);
            }
            return tmp1;
        }
    }
}
