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
    public class RAService
    {
        private readonly IMongoCollection<CsrModel> _CsrModel;
        private readonly IMongoCollection<BsonDocument> _Contries;
        private readonly IMongoCollection<ServiceModel> _ServiceModel;
        private readonly IMongoCollection<CertModel> _Cert;
        private readonly IMongoCollection<CrlModel> _Clr;
        public RAService(IDatabaseSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);
            _CsrModel = database.GetCollection<CsrModel>(settings.Csr);
            _Contries = database.GetCollection<BsonDocument>(settings.Countries);
            _ServiceModel = database.GetCollection<ServiceModel>(settings.Services);
            _Cert = database.GetCollection<CertModel>(settings.Cert);
            _Clr = database.GetCollection<CrlModel>(settings.Clr);
        }
        public CrlModel GetCrl(long Serial)
        {
            CrlModel result = _Clr.Find<CrlModel>(CrlModel => CrlModel.Serial == Serial).FirstOrDefault();
            return result;
        }
        public long MaxSerial()
        {
            return _Clr.AsQueryable<CrlModel>().Select(c => c.Serial).Max();
        }
        public IEnumerable<CrlModel> GetClrs()
        {
            FilterDefinition<CrlModel> filter = Builders<CrlModel>.Filter.Empty;
            //var projectionBuilder = Builders<CsrModel>.Projection;
            var result = _Clr.Find<CrlModel>(filter).ToEnumerable();

            return result;
        }
        public CsrModel GetCsr(string id)
        {
            CsrModel result = _CsrModel.Find<CsrModel>(CsrModel => CsrModel.Id == id).FirstOrDefault();
            return result;
        }
        public IEnumerable<CertModel> GetCerts(string searchString)
        {

            FilterDefinition<CertModel> filter = Builders<CertModel>.Filter.Empty;

            //var projectionBuilder = Builders<CsrModel>.Projection;
            var result = _Cert.Find<CertModel>(filter).ToEnumerable();
            List<CertModel> filterList = new List<CertModel>();
            foreach (CertModel item in result)
            {
                if (item.SubjectDN.Contains(searchString) || item.Serial.ToString().Contains(searchString)) filterList.Add(item);
            }
            if (filterList.Count==0)
            {
                return result;
            }
            else
            {
                return filterList;
            }
            
        }
        public IEnumerable<CertModel> GetCerts()
        {
            FilterDefinition<CertModel> filter = Builders<CertModel>.Filter.Empty;
            
            //var projectionBuilder = Builders<CsrModel>.Projection;
            var result = _Cert.Find<CertModel>(filter).ToEnumerable();
            return result;
        }
        public CertModel GetCert(Int64 Serial)
        {
            CertModel result = _Cert.Find<CertModel>(CertModel => CertModel.Serial == Serial).FirstOrDefault();
            return result;

        }
        public void Create(CsrModel collection)
        {
            _CsrModel.InsertOne(collection);
        }
        public void Create(ServiceModel collection)
        {
            _ServiceModel.InsertOne(collection);
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
            var tmp1 = new List<SelectListItem>();
            BsonDocument bson = result.ElementAt(0);
            if(bson.ElementCount>0)
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
        public IEnumerable<SelectListItem> GetCities(string country,string state)
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
