using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Xml.Serialization;

namespace Cath
{
    public static class Utilities
    {
        public static T Clone<T>(T src)
        {
            MemoryStream ms = new MemoryStream();
            BinaryFormatter formatter = new BinaryFormatter();
            formatter.Serialize(ms, src);
            ms.Position = 0;
            //ms.Seek(0, SeekOrigin.Begin);
            T dest = (T)formatter.Deserialize(ms);
            ms.Dispose();
            return dest;
        }

        public static T LoadFromXML<T>(string path)
        {
            try
            {
                XmlSerializer xs = new XmlSerializer(typeof(T));
                FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);
                T t = (T)xs.Deserialize(fs);
                fs.Close();
                return t;
            }
            catch
            {
                return default(T);
            }
        }

        public static void WriteToXML<T>(T t, string path)
        {
            XmlSerializer xs = new XmlSerializer(typeof(T));
            FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write);
            xs.Serialize(fs, t);
            fs.Close();
        }

        public static T LoadFromBinary<T>(string path)
        {
            try
            {
                BinaryFormatter bf = new BinaryFormatter();
                FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);
                T t = (T)bf.Deserialize(fs);
                fs.Close();
                return t;
            }
            catch
            {
                return default(T);
            }
        }

        public static void WriteToBinary<T>(T t, string path)
        {
            BinaryFormatter bf = new BinaryFormatter();
            FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write);
            bf.Serialize(fs, t);
            fs.Close();
        }

        public static T JsonDeserialize<T>(string json)
        {
            try
            {
                using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
                    return (T)serializer.ReadObject(ms);
                }
            }
            catch
            {
                return default(T);
            }
        }

        public static string JsonSerializer<T>(T t)
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
            using (MemoryStream ms = new MemoryStream())
            {
                serializer.WriteObject(ms, t);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
    }
}
