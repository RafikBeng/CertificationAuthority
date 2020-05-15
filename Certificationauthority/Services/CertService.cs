using Certificationauthority.Models;
using Microsoft.AspNetCore.Mvc.Rendering;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certificationauthority.Services
{
    public class CertService
    {
        private readonly IMongoCollection<CertModel> _CertModel;
        private readonly IMongoCollection<BsonDocument> _Contries;
        private readonly IMongoCollection<CsrModel> _Csr;
        public CertService(IDatabaseSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);
            _CertModel = database.GetCollection<CertModel>(settings.Collection);
            _Contries = database.GetCollection<BsonDocument>(settings.Countries);
            _Csr = database.GetCollection<CsrModel>(settings.Csr);
        }
        public void Create(CertModel collection)
        {
            _CertModel.InsertOne(collection);
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
        public IEnumerable<CsrModel> GetCsrs()
        {
            FilterDefinition<CsrModel> filter = Builders<CsrModel>.Filter.Empty;
            var projectionBuilder = Builders<CsrModel>.Projection;
            var result = _Csr.Find<CsrModel>(filter).ToEnumerable();
            return result;
        }
        public CsrModel GetCsr(string id)
        {
            CsrModel result= _Csr.Find<CsrModel>(CsrModel => CsrModel.Id == id).FirstOrDefault();
            return result;
            
        }
        public IEnumerable<SelectListItem> Getstates(string name)
        {

            FilterDefinition<BsonDocument> filter = Builders<BsonDocument>.Filter.Eq("name", name);
            ProjectionDefinition<BsonDocument> projection = Builders<BsonDocument>.Projection.Include("states").Exclude("_id");
            var result = _Contries.Find<BsonDocument>(filter).Project(projection).ToList();
            var tmp1 = new List<SelectListItem>();
            BsonDocument bson = result.ElementAt(0);
            if (bson.ElementCount > 0)
            {
                BsonDocument bson1 = bson.ElementAt(0).Value.AsBsonDocument;


                foreach (var v in bson1)
                {

                    SelectListItem selectListItem = new SelectListItem(v.Name, v.Name);
                    tmp1.Add(selectListItem);
                }
            }

            return tmp1;

        }
       
        public IEnumerable<SelectListItem> GetCities(string country, string state)
        {

            FilterDefinition<BsonDocument> filter = Builders<BsonDocument>.Filter.Eq("name", country);
            ProjectionDefinition<BsonDocument> projection = Builders<BsonDocument>.Projection.Include("states").Exclude("_id");
            var result = _Contries.Find<BsonDocument>(filter).Project(projection).ToList();
            var tmp1 = new List<SelectListItem>();
            BsonDocument bson = result.ElementAt(0);
            if (bson.ElementCount > 0)
            {
                BsonDocument bson1 = bson.ElementAt(0).Value.AsBsonDocument;
                BsonArray bson2 = bson1.GetElement(state).Value.AsBsonArray;


                foreach (var v in bson2)
                {

                    SelectListItem selectListItem = new SelectListItem(v.AsString, v.AsString);
                    tmp1.Add(selectListItem);
                }
            }

            return tmp1;
        }

    }
}
