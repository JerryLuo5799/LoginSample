using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LoginSample
{
    public class LoginSecretKeyCore
    {
        /// <summary>
        /// 登录时使用的秘钥对
        /// </summary>
        private static ConcurrentDictionary<string, LoginSecretKey> _dicLoginSecretKey = new ConcurrentDictionary<string, LoginSecretKey>();

        /// <summary>
        /// 新增秘钥对
        /// </summary>
        /// <param name="secretId"></param>
        /// <returns>返回公钥</returns>
        public static string AddLoginSecret(string secretId)
        {
            var secretKey = new LoginSecretKey();

            RsaKey rsaKey = RsaCrypt.GenerateRsaKeys();

            secretKey.PublicKey = rsaKey.PublicKey;
            secretKey.PrivateKey = rsaKey.PrivateKey;

            _dicLoginSecretKey.TryAdd(secretId, secretKey);

            return secretKey.PublicKey;
        }

        /// <summary>
        /// 获取私钥
        /// </summary>
        /// <param name="secretId"></param>
        /// <returns>返回公钥</returns>
        public static string GetLoginPrivateKey(string secretId)
        {
            string privateKey = string.Empty;
            //获取一次就删除
            if (_dicLoginSecretKey.TryRemove(secretId, out var secretKey))
            {
                privateKey = secretKey.PrivateKey;
            }

            return privateKey;
        }
    }


    public class LoginSecretKey
    {
        /// <summary>
        /// 公钥
        /// </summary>
        public string PublicKey { get; set; }

        /// <summary>
        /// 私钥
        /// </summary>
        public string PrivateKey { get; set; }
    }

}
