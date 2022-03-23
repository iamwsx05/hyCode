using hyCode.ws;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace frmSM4Util
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            this.memoEdit1.Text = sm3();
            //this.memoEdit2.Text = sm4_decrypt_ECB();
            hyCodeService
        }


        public string sm3()
        {
            string json = string.Empty;
            //json += "{";
            //json += string.Format("\"appId\":\"{0}\",","60C90F3B796B41878B8D9C393E2B6329");
            //json += string.Format("\"nonceStr\":\"{0}\",", "1234567890");
            //json += string.Format("\"timestamp\":\"{0}\",", "60C90F3B796B41878B8D9C393E2B6329");
            //json += "\"version\":\"V2.0.0\"";
            //json += "}";

            string key = "F2D8D966CD3D47788449C19D5EF2081B";
            json += "{";
            json += "\"key\": \"F2D8D966CD3D47788449C19D5EF2081B\",";
            json += "\"mode\":\"SM3\",";
            json += "\"body\":{";
            json += "\"appId\":\"60C90F3B796B41878B8D9C393E2B6329\",";
            json += "\"nonceStr\":\".88357776802397576516672734238763958247\",";
            json += "\"orgCode\":\"LDWLYXGS\",";
            json += "\"timestamp\":\"1541816252.000000000000000000000000000004\",";
            json += "\"version\":\"V1.0.2\"";
            json += "}";
            json += "}";


            string encrypt = Sm3Utils.encrypt(json + key);

            return encrypt;
        }


        public string sm4_encryptEcb()
        {
            string encryptEcb = string.Empty;


            //SM4Util sm4Util = new SM4Util();
            //sm4Util.secretKey = "F2D8D966CD3D47788449C19D5EF2081B";
            ////sm4Util.iv = "450422199206240849";
            //string plaintext = "450422199206240849";
            //encryptEcb = sm4Util.Encrypt_ECB(plaintext);

            //MainSm4 sm4 = new MainSm4();
            // encryptEcb = sm4.Encrypt_ECB("F2D8D966CD3D47788449C19D5EF2081B", true, "450422199206240849");

            byte[] plaintext = Encoding.ASCII.GetBytes("Hello World");
            byte[] keyBytes = Encoding.ASCII.GetBytes("0123456789ABCDEF");
            byte[] iv = Encoding.ASCII.GetBytes("0123456789ABCDEF");
            // 加密
            KeyParameter key = ParameterUtilities.CreateKeyParameter("SM4", keyBytes);
            ParametersWithIV keyParamWithIv = new ParametersWithIV(key, iv);

            IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CBC/PKCS7Padding");
            inCipher.Init(true, keyParamWithIv);
            byte[] cipher = inCipher.DoFinal(plaintext);
            Console.WriteLine("加密后的密文(hex): {0}", BitConverter.ToString(cipher, 0).Replace("-", string.Empty));


            encryptEcb = BitConverter.ToString(cipher, 0).Replace("-", string.Empty);

            return encryptEcb;
        }

        public string sm4_decrypt_ECB()
        {
            string decryptEcb = string.Empty;


            //SM4Util sm4Util = new SM4Util();
            //sm4Util.secretKey = "F2D8D966CD3D47788449C19D5EF2081B";
            ////sm4Util.iv = "8DAD69F1A99DC5FD79FE9CB8D8FFD022499DDD6FCAEC433D690FACF545D8E49A";
            //string plaintext = "8DAD69F1A99DC5FD79FE9CB8D8FFD022499DDD6FCAEC433D690FACF545D8E49A";
            //decryptEcb = sm4Util.Decrypt_ECB(plaintext);
            return decryptEcb;
        }
    }
}
