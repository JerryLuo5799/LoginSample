using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace LoginSample
{
    /// <summary>
    /// 得到随机安全码（哈希加密）。
    /// </summary>
    public static class HashEncode
    {

        /// <summary>
        /// 生成真正的随机数
        /// </summary>
        /// <param name="r"></param>
        /// <param name="seed"></param>
        /// <returns></returns>
        public static int StrictNext(this Random r, int seed = int.MaxValue)
        {
            return new Random((int)Stopwatch.GetTimestamp()).Next(seed);
        }

        /// <summary>
        /// 得到随机哈希加密字符串
        /// </summary>
        /// <returns>随机哈希加密字符串</returns>
        public static string GetSecurity(this Random r) => HashEncoding(r.StrictNext().ToString());

        /// <summary>
        /// 哈希加密一个字符串
        /// </summary>
        /// <param name="security">需要加密的字符串</param>
        /// <returns>加密后的数据</returns>
        public static string HashEncoding(this string security)
        {
            var code = new UnicodeEncoding();
            byte[] message = code.GetBytes(security);
            using var arithmetic = new SHA512Managed();
            var value = arithmetic.ComputeHash(message);
            var sb = new StringBuilder();
            foreach (byte o in value)
            {
                sb.Append((int)o + "O");
            }

            return sb.ToString();
        }
    }
}