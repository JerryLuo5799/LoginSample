using Microsoft.AspNetCore.Mvc;
using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LoginSample.Controllers
{
    /// <summary>
    /// 用户相关操作方法
    /// </summary>
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {

        private string _AESDecryptkey = "olsTrYCEiNugHtoM";

        /// <summary>
        /// 使用SQL的登录方法
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("LoginBySQL")]
        public JsonResult LoginBySQL([FromBody]LoginRequest request)
        {
            var retValue = new LoginResponse();

            string sql = @"select * from t_user where user_name='" + request.UserName + "' and user_password='" + request.Password + "' limit 1";

            var password = request.Password.AESEncrypt(_AESDecryptkey);

            DataTable dt = new DataTable();

            using (MySqlConnection conn = new MySqlConnection(AppSetting.DefaultConnection))
            {
                conn.Open();
                MySqlDataAdapter adapter = new MySqlDataAdapter(sql, conn);
                adapter.SelectCommand.CommandType = CommandType.Text;
                adapter.Fill(dt);
            }
            
            if(null != dt && dt.Rows.Count > 0)
            {
                retValue.code = "8200";
                retValue.msg = "登录成功";
                retValue.token = Guid.NewGuid().ToString();
            }
            else
            {
                retValue.code = "8500";
                retValue.msg = "用户名或密码错误";
            }

            return new JsonResult(retValue);
        }

        /// <summary>
        /// 使用SQL的登录方法
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("LoginBySQLParameter")]
        public JsonResult LoginBySQLParameter([FromBody] LoginRequest request)
        {
            var retValue = new LoginResponse();

            string sql = @"select * from t_user where user_name=@userName and user_password=@password limit 1";

            MySqlParameter[] param ={
                    new MySqlParameter("@userName",MySqlDbType.VarChar,50),
                    new MySqlParameter("@password",MySqlDbType.VarChar,50)
            };
            param[0].Value = request.UserName;
            param[1].Value = request.Password;

            DataTable dt = new DataTable();

            using (MySqlConnection conn = new MySqlConnection(AppSetting.DefaultConnection))
            {
                conn.Open();
                MySqlDataAdapter adapter = new MySqlDataAdapter(sql, conn);
                adapter.SelectCommand.CommandType = CommandType.Text;
                //填充SQL参数
                adapter.SelectCommand.Parameters.AddRange(param);
                adapter.Fill(dt);
            }

            if (null != dt && dt.Rows.Count > 0)
            {
                retValue.code = "8200";
                retValue.msg = "登录成功";
                retValue.token = Guid.NewGuid().ToString();
            }
            else
            {
                retValue.code = "8500";
                retValue.msg = "用户名或密码错误";
            }

            return new JsonResult(retValue);
        }

        /// <summary>
        /// 使用SQL的登录方法
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("LoginByEncryptPassword")]
        public JsonResult LoginByEncryptPassword([FromBody] LoginRequest request)
        {
            var retValue = new LoginResponse();
            retValue.code = "8500";
            retValue.msg = "用户名或密码错误";

            string sql = @"select * from t_user where user_name=@userName limit 1";

            MySqlParameter[] param ={
                    new MySqlParameter("@userName",MySqlDbType.VarChar,50)
            };
            param[0].Value = request.UserName;

            DataTable dt = new DataTable();
            #region SQL查询

            using (MySqlConnection conn = new MySqlConnection(AppSetting.DefaultConnection))
            {
                conn.Open();
                MySqlDataAdapter adapter = new MySqlDataAdapter(sql, conn);
                adapter.SelectCommand.CommandType = CommandType.Text;
                //填充SQL参数
                adapter.SelectCommand.Parameters.AddRange(param);
                adapter.Fill(dt);
            }

            #endregion
            if (null != dt && dt.Rows.Count > 0)
            {
                //判断输入密码的Hash值是否等于数据库中存储的值
                string userPassword = dt.Rows[0]["user_password"].ToString();
                string salt = dt.Rows[0]["salt"].ToString();

                //计算输入密码的Hash值
                string passwordHash = request.Password.MDString3(salt);

                if(passwordHash == userPassword)
                {
                    retValue.code = "8200";
                    retValue.msg = "登录成功";
                    retValue.token = Guid.NewGuid().ToString();
                }             
            }

            return new JsonResult(retValue);
        }

        /// <summary>
        /// 使用SQL的登录方法
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("LoginByFrontEncryptPassword")]
        public JsonResult LoginByFrontEncryptPassword([FromBody] LoginRequest request)
        {
            var retValue = new LoginResponse();
            retValue.code = "8500";
            retValue.msg = "用户名或密码错误";

            string sql = @"select * from t_user where user_name=@userName limit 1";

            MySqlParameter[] param ={
                    new MySqlParameter("@userName",MySqlDbType.VarChar,50)
            };
            param[0].Value = request.UserName;

            DataTable dt = new DataTable();
            #region SQL查询

            using (MySqlConnection conn = new MySqlConnection(AppSetting.DefaultConnection))
            {
                conn.Open();
                MySqlDataAdapter adapter = new MySqlDataAdapter(sql, conn);
                adapter.SelectCommand.CommandType = CommandType.Text;
                //填充SQL参数
                adapter.SelectCommand.Parameters.AddRange(param);
                adapter.Fill(dt);
            }

            #endregion
            if (null != dt && dt.Rows.Count > 0)
            {
                //判断输入密码的Hash值是否等于数据库中存储的值
                string userPassword = dt.Rows[0]["user_password"].ToString();
                string salt = dt.Rows[0]["salt"].ToString();

                //解密前端密码
                string decodePassword = request.Password.AESDecrypt(_AESDecryptkey);

                //计算输入密码的Hash值
                string passwordHash = decodePassword.MDString3(salt);

                if (passwordHash == userPassword)
                {
                    retValue.code = "8200";
                    retValue.msg = "登录成功";
                    retValue.token = Guid.NewGuid().ToString();
                }
            }

            return new JsonResult(retValue);
        }


        /// <summary>
        /// 获取秘钥对
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("GetLoginSecretKey")]
        public JsonResult GetLoginSecretKey()
        {
            var retValue = new LoginSecretKeyResponse();
            retValue.code = "8200";
            retValue.secretId = Guid.NewGuid().ToString();
            retValue.publicKey = LoginSecretKeyCore.AddLoginSecret(retValue.secretId);

            return new JsonResult(retValue);
        }

        //var password = "j6424hnrqm5b".RSAEncrypt(retValue.publicKey);


        /// <summary>
        /// 使用SQL的登录方法
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("LoginByRSAPassword")]
        public JsonResult LoginByRSAPassword([FromBody] LoginRSARequest request)
        {
            var retValue = new LoginResponse();
            retValue.code = "8500";
            retValue.msg = "用户名或密码错误";

            string sql = @"select * from t_user where user_name=@userName limit 1";

            MySqlParameter[] param ={
                    new MySqlParameter("@userName",MySqlDbType.VarChar,50)
            };
            param[0].Value = request.UserName;

            DataTable dt = new DataTable();
            #region SQL查询

            using (MySqlConnection conn = new MySqlConnection(AppSetting.DefaultConnection))
            {
                conn.Open();
                MySqlDataAdapter adapter = new MySqlDataAdapter(sql, conn);
                adapter.SelectCommand.CommandType = CommandType.Text;
                //填充SQL参数
                adapter.SelectCommand.Parameters.AddRange(param);
                adapter.Fill(dt);
            }

            #endregion
            if (null != dt && dt.Rows.Count > 0)
            {
                //判断输入密码的Hash值是否等于数据库中存储的值
                string userPassword = dt.Rows[0]["user_password"].ToString();
                string salt = dt.Rows[0]["salt"].ToString();

                try
                {
                    //获取私钥
                    string privateKey = LoginSecretKeyCore.GetLoginPrivateKey(request.SecretId);
                    //解密前端密码
                    string decodePassword = request.Password.RSADecrypt(privateKey);

                    //计算输入密码的Hash值
                    string passwordHash = decodePassword.MDString3(salt);

                    if (passwordHash == userPassword)
                    {
                        retValue.code = "8200";
                        retValue.msg = "登录成功";
                        retValue.token = Guid.NewGuid().ToString();
                    }
                }
                catch
                {
                    retValue.code = "8500";
                    retValue.msg = "无效秘钥对";
                }
              
            }

            return new JsonResult(retValue);
        }


        /// <summary>
        /// 获取密码hash
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        private string GetPasswordHash(string password)
        {
            return password;
        }

        /// <summary>
        /// 获取密码hash
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        private string MDString3(string password)
        {
            return password;
        }

 
    }

    /// <summary>
    /// 登录请求类
    /// </summary>
    public class LoginRequest
    {
        public string UserName { get; set; }

        public string Password { get; set; }
    }

    /// <summary>
    /// 登录请求类
    /// </summary>
    public class LoginRSARequest : LoginRequest
    {
        public string SecretId { get; set; }

    }

    /// <summary>
    /// 登录请求类
    /// </summary>
    public class LoginResponse
    {
        public string code { get; set; } = string.Empty;

        public string msg { get; set; } = string.Empty;

        public string token { get; set; } = string.Empty;
    }

    /// <summary>
    /// 获取登录公钥请求类
    /// </summary>
    public class LoginSecretKeyResponse
    {
        public string code { get; set; } = string.Empty;

        public string msg { get; set; } = string.Empty;

        public string secretId { get; set; } = string.Empty;

        public string publicKey { get; set; } = string.Empty;
    }
}


