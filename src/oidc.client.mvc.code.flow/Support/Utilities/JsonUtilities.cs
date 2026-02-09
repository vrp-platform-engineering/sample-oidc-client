using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace oidc.client.mvc.code.flow.Support.Utilities
{
    public static class JsonUtilities
    {
        #region events.

        public delegate JsonSerializerSettings JsonSerializerSettingsDelegate(JsonSerializerSettings source);
        public static event JsonSerializerSettingsDelegate JsonSerializerSettingsEvent;

        #endregion
        #region statics.

        public static string Serialize(object value)
        {
            return Serialize(value, GetDefaultSerializationSettings());
        }
        public static string Serialize<T>(T value)
        {
            return Serialize(value, GetDefaultSerializationSettings());
        }
        public static T Deserialize<T>(string json)
        {
            return Deserialize<T>(json, GetDefaultSerializationSettings());
        }
        public static object Deserialize(string json, Type type)
        {
            return Deserialize(json, type, GetDefaultSerializationSettings());
        }

        public static string Serialize<T>(T value, JsonSerializerSettings settings)
        {
            try
            {
                return value != null
                     ? JsonConvert.SerializeObject(value, settings)
                     : null;
            }
            catch
            {
                throw;
                //return null;
            }
        }
        public static string Serialize<T>(T value, Formatting formatting)
        {
            try
            {
                return value != null
                     ? JsonConvert.SerializeObject(value, formatting, GetDefaultSerializationSettings())
                     : null;
            }
            catch
            {
                throw;
                //return null;
            }
        }
        public static string Serialize<T>(T value, Formatting formatting, JsonSerializerSettings settings)
        {
            try
            {
                return value != null
                     ? JsonConvert.SerializeObject(value, formatting, settings)
                     : null;
            }
            catch
            {
                throw;
                //return null;
            }
        }

        public static T Deserialize<T>(string json, JsonSerializerSettings settings)
        {
            try
            {
                return json != null ? JsonConvert.DeserializeObject<T>(json, settings) : default;
            }
            catch (Exception)
            {
                throw;
                //return default( T );
            }
        }
        public static object Deserialize(string json, Type type, JsonSerializerSettings settings)
        {
            try
            {
                return json != null ? JsonConvert.DeserializeObject(json, type, settings) : default;
            }
            catch
            {
                throw;
                //return default( T );
            }
        }

        public static object ToObject(this System.Text.Json.JsonElement element, Type requestType)
        {
            var json = element.GetRawText();
            return System.Text.Json.JsonSerializer.Deserialize(json, requestType);
        }
        public static T ToObject<T>(this System.Text.Json.JsonElement element)
        {
            var json = element.GetRawText();
            return System.Text.Json.JsonSerializer.Deserialize<T>(json);
        }

        private static JsonSerializerSettings GetInternalSerializationSettings()
        {
            var settings = new JsonSerializerSettings()
            {
                TypeNameHandling = TypeNameHandling.Auto,
                TypeNameAssemblyFormatHandling = TypeNameAssemblyFormatHandling.Full,
                ObjectCreationHandling = ObjectCreationHandling.Replace,
                DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate,
                NullValueHandling = NullValueHandling.Ignore,
                MissingMemberHandling = MissingMemberHandling.Ignore,
                ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
                PreserveReferencesHandling = PreserveReferencesHandling.Objects,
                ContractResolver = new DefaultContractResolver()
                //DateTimeZoneHandling = DateTimeZoneHandling.Local,
            };

            return settings;
        }
        public static JsonSerializerSettings GetDefaultSerializationSettings()
        {
            return JsonSerializerSettingsEvent?.Invoke(GetInternalSerializationSettings())
                ?? GetInternalSerializationSettings();
        }

        public static string Beautify(string json)
        {
            JToken parsedJson = JToken.Parse(json);
            return parsedJson.ToString(Formatting.Indented);
        }

        #endregion
    }
}
