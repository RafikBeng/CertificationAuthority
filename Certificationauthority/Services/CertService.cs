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
        private readonly IMongoCollection<CertModel> _Cert;
        private readonly IMongoCollection<BsonDocument> _Contries;
        private readonly IMongoCollection<CsrModel> _Csr;
        private readonly IMongoCollection<ServiceModel> _Service;
        private readonly IMongoCollection<ClrModel> _Clr;
        public CertService(IDatabaseSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);
            _Cert = database.GetCollection<CertModel>(settings.Cert);
            _Contries = database.GetCollection<BsonDocument>(settings.Countries);
            _Csr = database.GetCollection<CsrModel>(settings.Csr);
            _Service = database.GetCollection<ServiceModel>(settings.Services);
            _Clr = database.GetCollection<ClrModel>(settings.Clr);
        }
        public void Create(CertModel collection)
        {
            _Cert.InsertOne(collection);
        }
        public void Create(ClrModel collection)
        {
            _Clr.InsertOne(collection);
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
        public IEnumerable<ServiceModel> GetServices()
        {
            FilterDefinition<ServiceModel> filter = Builders<ServiceModel>.Filter.Empty;
            //var projectionBuilder = Builders<CsrModel>.Projection;
            var result = _Service.Find<ServiceModel>(filter).ToEnumerable();
            return result;
        }
        public IEnumerable<CsrModel> GetCsrs()
        {
            FilterDefinition<CsrModel> filter = Builders<CsrModel>.Filter.Empty;
            //var projectionBuilder = Builders<CsrModel>.Projection;
            var result = _Csr.Find<CsrModel>(filter).ToEnumerable();
            return result;
        }
        public IEnumerable<ClrModel> GetClrs()
        {
            FilterDefinition<ClrModel> filter = Builders<ClrModel>.Filter.Empty;
            //var projectionBuilder = Builders<CsrModel>.Projection;
            var result = _Clr.Find<ClrModel>(filter).ToEnumerable();
            return result;
        }
        public IEnumerable<CertModel> GetCerts()
        {
            FilterDefinition<CertModel> filter = Builders<CertModel>.Filter.Empty;
            //var projectionBuilder = Builders<CsrModel>.Projection;
            var result = _Cert.Find<CertModel>(filter).ToEnumerable();
            return result;
        }
        public CsrModel GetCsr(string id)
        {
            CsrModel result= _Csr.Find<CsrModel>(CsrModel => CsrModel.Id == id).FirstOrDefault();
            return result;   
        }
        public ServiceModel GetService(string id)
        {
            ServiceModel result = _Service.Find<ServiceModel>(ServiceModel => ServiceModel.Id == id).FirstOrDefault();
            return result;
        }
        public CertModel GetCert(bool IsRootCA)
        {
            CertModel result = _Cert.Find<CertModel>(CertModel => CertModel.IsRootCA == IsRootCA).FirstOrDefault();
            return result;

        }
        public CertModel GetCert(Int64 Serial)
        {
            CertModel result = _Cert.Find<CertModel>(CertModel => CertModel.Serial == Serial).FirstOrDefault();
            return result;

        }
        public void DelServices(string id)
        {
            _Service.DeleteOne<ServiceModel>(ServiceModel => ServiceModel.Id == id);
        }
        public void DelCsr(string id)
        {
            _Csr.DeleteOne<CsrModel>(CsrModel => CsrModel.Id == id);
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
