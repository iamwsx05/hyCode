using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace frmSM4Util
{
    public class Sm3Utils
    {
        private static  string ENCODING = "UTF-8";
        public static string encrypt(string paramStr)
        {
            // 将返回的hash值转换成16进制字符串
            string resultHexString = "";
            try
            {
                // 将字符串转换成byte数组
                byte[] srcData = System.Text.Encoding.UTF8.GetBytes(paramStr);
                // 调用hash()
                byte[] resultHash = hash(srcData);
                // 将返回的hash值转换成16进制字符串
                resultHexString = new UTF8Encoding().GetString(Hex.Encode(resultHash));
            }
            catch (Exception ex)
            {
               // ExceptionLog.OutPutException(ex);
            }
            return resultHexString;
        }


        /**
         * 返回长度=32的byte数组
         * 
         * @explain 生成对应的hash值
         * @param srcData
         * @return
         */
        public static byte[] hash(byte[] srcData)
        {
            SM3Digest digest = new SM3Digest();
            digest.BlockUpdate(srcData, 0, srcData.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }

        /**
         * 通过密钥进行加密
         * 
         * @explain 指定密钥进行加密
         * @param key
         *            密钥
         * @param srcData
         *            被加密的byte数组
         * @return
         */
        public static byte[] hmac(byte[] key, byte[] srcData)
        {
            KeyParameter keyParameter = new KeyParameter(key);
            SM3Digest digest = new SM3Digest();
            HMac mac = new HMac(digest);
            mac.Init(keyParameter);
            mac.BlockUpdate(srcData, 0, srcData.Length);
            byte[] result = new byte[mac.GetMacSize()];
            mac.DoFinal(result, 0);
            return result;
        }
    }
}
