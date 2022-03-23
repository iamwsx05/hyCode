using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Services;
using System.Xml;
using weCare.Core.Utils;

namespace hyCode.ws
{
    /// <summary>
    /// hyCodeService 的摘要说明
    /// </summary>
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    // 若要允许使用 ASP.NET AJAX 从脚本中调用此 Web 服务，请取消注释以下行。 
    // [System.Web.Script.Services.ScriptService]
    public class hyCodeService : System.Web.Services.WebService
    {
        #region var/property
        string encryptUrl = "http://192.168.1.13:8098/api/encrypt";
        string decipheringUrl = "http://192.168.1.13:8098/api/deciphering";
        string signUrl = "http://192.168.1.13:8098/api/sign";
        string apiUrl = "http://192.168.1.13:8098/api/do";
        //string apiUrl = "http://192.168.1.13:8099/api/do";
        string appId = "60C90F3B796B41878B8D9C393E2B6329";
        string key = "F2D8D966CD3D47788449C19D5EF2081B";
        string orgCode = "KGA00020100000014";
        string appRecordNo = "1301A0002QTHX0001";
        //int proxy = 0;
        #endregion


        #region 6.1	电子健康码注册
        /// <summary>
        /// 6.1	电子健康码注册
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [WebMethod]
        public string createVmcardQRcode(string request)
        {
            string response = string.Empty;

            //proxy =Function.Int(ReadXmlConfig("proxy"))  ;
            //if (proxy == 1)
            //{
            //    hyCodeService svc = new hyCodeService();
            //    response = svc.createVmcardQRcode(request);
            //}
            //else
            {
                string caption = "电子健康码注册";
                if (string.IsNullOrEmpty(request)) return string.Empty;
                Log.OutputXml(caption + ":\r\n" + request);

                string reqJson = string.Empty;
                
                try
                {
                    appId = ReadXmlConfig("appId");
                    key = ReadXmlConfig("key");
                    orgCode = ReadXmlConfig("orgCode");
                    appRecordNo = ReadXmlConfig("appRecordNo");

                    EntityRes01 resVo = null;
                    Dictionary<string, string> dic = Function.ReadXmlNodes(request, "req");

                    string name = dic["name"].ToString();
                    name = Encrypt(name);
                    string idCardTypeCode = dic["idCardTypeCode"].ToString();
                    string idCode = dic["idCode"].ToString();
                    idCode = Encrypt(idCode);
                    string validStartdate = dic["validStartdate"].ToString();
                    string validEnddate = dic["validEnddate"].ToString();
                    string idInst = dic["idInst"].ToString();
                    string sex = dic["sex"].ToString();
                    string nation = dic["nation"].ToString();
                    string birthday = dic["birthday"].ToString();
                    string birthplace = dic["birthplace"].ToString();
                    string phone = dic["phone"].ToString();
                    if (!string.IsNullOrEmpty(phone))
                        phone = Encrypt(phone);

                    string linkman = dic["linkman"].ToString();
                    if (!string.IsNullOrEmpty(linkman))
                        linkman = Encrypt(linkman);

                    string telephone = dic["telephone"].ToString();
                    if (!string.IsNullOrEmpty(telephone))
                        telephone = Encrypt(telephone);
                    string address = dic["address"].ToString();
                    string currentAddress = dic["currentAddress"].ToString();
                    string maritalstatuscode = dic["maritalstatuscode"].ToString();
                    string idPhoto = dic["idPhoto"].ToString();
                    string scenePhoto = dic["scenePhoto"].ToString();
                    string nationality = dic["nationality"].ToString();
                    string language = dic["language"].ToString();
                    string personnelType = dic["personnelType"].ToString();

                    string multifetalMark = string.Empty;
                    string multpripleBirths = string.Empty;
                    string motherName = string.Empty;
                    string motherIdCode = string.Empty;
                    string motherEmpi = string.Empty;
                    if (personnelType == "2")
                    {
                        multifetalMark = dic["multifetalMark"].ToString();
                        multpripleBirths = dic["multpripleBirths"].ToString();
                        motherName = dic["motherName"].ToString();
                        if (!string.IsNullOrEmpty(motherName))
                            motherName = Encrypt(motherName);
                        motherIdCode = dic["motherIdCode"].ToString();
                        if (!string.IsNullOrEmpty(motherIdCode))
                            motherIdCode = Encrypt(motherIdCode);
                        motherEmpi = dic["motherEmpi"].ToString();
                    }

                    string appMode = dic["appMode"].ToString();
                    string payAccType = dic["payAccType"].ToString();

                    //时间戳
                    string timestamp = GetTimeStamp();
                    timestamp = Encrypt(timestamp);

                    string nonceStr = "1234567890";
                    string bodySign = string.Empty;
                    string headSign = string.Empty;

                    //头部签名
                    string headJson = string.Empty;
                    headJson += "{";
                    headJson += string.Format("\"key\": \"{0}\",", key);
                    headJson += "\"mode\":\"SM3\",";
                    headJson += "\"body\":{";
                    headJson += string.Format("\"appId\":\"{0}\",", appId);
                    headJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr);
                    headJson += string.Format("\"timestamp\":\"{0}\",", timestamp);
                    headJson += "\"version\":\"V2.0.0\"";
                    headJson += "}";
                    headJson += "}";
                    resVo = Sm3Sign(headJson);
                    if (resVo != null)
                        headSign = resVo.result;

                    //数据签名
                    string bodyJson = string.Empty;
                    bodyJson += "{" + Environment.NewLine; ;
                    bodyJson += string.Format("\"key\": \"{0}\",", key) + Environment.NewLine; ;
                    bodyJson += "\"mode\":\"SM3\"," + Environment.NewLine; ;
                    bodyJson += "\"body\":{ " + Environment.NewLine; ;
                    bodyJson += string.Format("\"name\":\"{0}\",", name) + Environment.NewLine;
                    bodyJson += string.Format("\"idCardTypeCode\":\"{0}\",", idCardTypeCode) + Environment.NewLine;
                    bodyJson += string.Format("\"idCode\":\"{0}\",", idCode) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(validStartdate))
                        bodyJson += string.Format("\"validStartdate\":\"{0}\",", validStartdate) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(validEnddate))
                        bodyJson += string.Format("\"validEnddate\":\"{0}\",", validEnddate) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(idInst))
                        bodyJson += string.Format("\"idInst\":\"{0}\",", idInst) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(sex))
                        bodyJson += string.Format("\"sex\":\"{0}\",", sex) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(nation))
                        bodyJson += string.Format("\"nation\":\"{0}\",", nation) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(birthday))
                        bodyJson += string.Format("\"birthday\":\"{0}\",", birthday) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(birthplace))
                        bodyJson += string.Format("\"birthplace\":\"{0}\",", birthplace) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(phone))
                        bodyJson += string.Format("\"phone\":\"{0}\",", phone) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(linkman))
                        bodyJson += string.Format("\"linkman\":\"{0}\",", linkman) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(telephone))
                        bodyJson += string.Format("\"telephone\":\"{0}\",", telephone) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(address))
                        bodyJson += string.Format("\"address\":\"{0}\",", address) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(currentAddress))
                        bodyJson += string.Format("\"currentAddress\":\"{0}\",", currentAddress) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(maritalstatuscode))
                        bodyJson += string.Format("\"maritalstatuscode\":\"{0}\",", maritalstatuscode) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(idPhoto))
                        bodyJson += string.Format("\"idPhoto\":\"{0}\",", idPhoto) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(scenePhoto))
                        bodyJson += string.Format("\"scenePhoto\":\"{0}\",", scenePhoto) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(nationality))
                        bodyJson += string.Format("\"nationality\":\"{0}\",", nationality) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(language))
                        bodyJson += string.Format("\"language\":\"{0}\",", language) + Environment.NewLine;
                    bodyJson += string.Format("\"personnelType\":\"{0}\",", personnelType) + Environment.NewLine;
                    if (personnelType == "2")
                    {
                        bodyJson += string.Format("\"multifetalMark\":\"{0}\",", multifetalMark) + Environment.NewLine;
                        bodyJson += string.Format("\"multpripleBirths\":\"{0}\",", multpripleBirths) + Environment.NewLine;
                        bodyJson += string.Format("\"motherName\":\"{0}\",", motherName) + Environment.NewLine;
                        bodyJson += string.Format("\"motherIdCode\":\"{0}\",", motherIdCode) + Environment.NewLine;
                        bodyJson += string.Format("\"motherEmpi\":\"{0}\",", motherEmpi) + Environment.NewLine;
                    }
                    bodyJson += string.Format("\"appMode\":\"{0}\",", appMode) + Environment.NewLine;
                    bodyJson += string.Format("\"payAccType\":\"{0}\",", payAccType) + Environment.NewLine;
                    bodyJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    bodyJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    bodyJson += "}" + Environment.NewLine;
                    bodyJson += "}";
                    resVo = Sm3Sign(bodyJson);
                    if (resVo != null)
                        bodySign = resVo.result;

                    //请求报文
                    reqJson += "{" + Environment.NewLine;
                    reqJson += "\"method\":\"createVmcardQRcode\"," + Environment.NewLine;
                    reqJson += string.Format("\"headSign\":\"{0}\",", headSign) + Environment.NewLine;
                    reqJson += string.Format("\"bodySign\":\"{0}\",", bodySign) + Environment.NewLine;
                    reqJson += "\"version\":\"V2.0.0\"," + Environment.NewLine;
                    reqJson += string.Format("\"appId\":\"{0}\",", appId) + Environment.NewLine;
                    reqJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr) + Environment.NewLine;
                    reqJson += string.Format("\"timestamp\":\"{0}\",", timestamp) + Environment.NewLine;
                    reqJson += "\"signMode\":\"SM3\"," + Environment.NewLine;
                    reqJson += "\"encryptMode\":\"SM4/ECB/ZeroBytePadding\"," + Environment.NewLine;
                    reqJson += "\"body\":{ " + Environment.NewLine;
                    reqJson += string.Format("\"name\":\"{0}\",", name) + Environment.NewLine;
                    reqJson += string.Format("\"idCardTypeCode\":\"{0}\",", idCardTypeCode) + Environment.NewLine;
                    reqJson += string.Format("\"idCode\":\"{0}\",", idCode) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(validStartdate))
                        reqJson += string.Format("\"validStartdate\":\"{0}\",", validStartdate) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(validEnddate))
                        reqJson += string.Format("\"validEnddate\":\"{0}\",", validEnddate) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(idInst))
                        reqJson += string.Format("\"idInst\":\"{0}\",", idInst) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(sex))
                        reqJson += string.Format("\"sex\":\"{0}\",", sex) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(nation))
                        reqJson += string.Format("\"nation\":\"{0}\",", nation) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(birthday))
                        reqJson += string.Format("\"birthday\":\"{0}\",", birthday) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(birthplace))
                        reqJson += string.Format("\"birthplace\":\"{0}\",", birthplace) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(phone))
                        reqJson += string.Format("\"phone\":\"{0}\",", phone) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(linkman))
                        reqJson += string.Format("\"linkman\":\"{0}\",", linkman) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(telephone))
                        reqJson += string.Format("\"telephone\":\"{0}\",", telephone) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(address))
                        reqJson += string.Format("\"address\":\"{0}\",", address) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(currentAddress))
                        reqJson += string.Format("\"currentAddress\":\"{0}\",", currentAddress) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(maritalstatuscode))
                        reqJson += string.Format("\"maritalstatuscode\":\"{0}\",", maritalstatuscode) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(idPhoto))
                        reqJson += string.Format("\"idPhoto\":\"{0}\",", idPhoto) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(scenePhoto))
                        reqJson += string.Format("\"scenePhoto\":\"{0}\",", scenePhoto) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(nationality))
                        reqJson += string.Format("\"nationality\":\"{0}\",", nationality) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(language))
                        reqJson += string.Format("\"language\":\"{0}\",", language) + Environment.NewLine;
                    reqJson += string.Format("\"personnelType\":\"{0}\",", personnelType) + Environment.NewLine;
                    if (personnelType == "2")
                    {
                        reqJson += string.Format("\"multifetalMark\":\"{0}\",", multifetalMark) + Environment.NewLine;
                        reqJson += string.Format("\"multpripleBirths\":\"{0}\",", multpripleBirths) + Environment.NewLine;
                        reqJson += string.Format("\"motherName\":\"{0}\",", motherName) + Environment.NewLine;
                        reqJson += string.Format("\"motherIdCode\":\"{0}\",", motherIdCode) + Environment.NewLine;
                        reqJson += string.Format("\"motherEmpi\":\"{0}\",", motherEmpi) + Environment.NewLine;
                    }
                    reqJson += string.Format("\"appMode\":\"{0}\",", appMode) + Environment.NewLine;
                    reqJson += string.Format("\"payAccType\":\"{0}\",", payAccType) + Environment.NewLine;
                    reqJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    reqJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    reqJson += "}" + Environment.NewLine;
                    reqJson += "}";

                    Log.Output(reqJson);

                    response = httpPost(reqJson);
                    Log.Output(response);
                    //if (!string.IsNullOrEmpty(response))
                    //{
                    //    XmlDocument doc =JsonHelper.Json2Xml(response);
                    //    response = doc.OuterXml.ToString().Replace("<?xml version=\"1.0\" encoding=\"gb2312\" standalone=\"yes\"?>", " ");
                    //}
                }
                catch (Exception ex)
                {
                    Log.OutputXml(caption + ":\r\n" + ex.Message);
                }  
            }

            return response;

        }

        #endregion

        #region 6.2	电子健康码个人信息修改
        /// <summary>
        /// 6.2	电子健康码个人信息修改
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [WebMethod]
        public string modifyVmcardInfo(string request)
        {
            string response = string.Empty;
            //proxy = Function.Int(ReadXmlConfig("proxy"));
            //if (proxy == 1)
            //{
            //    hyCodeService svc = new hyCodeService();
            //    response = svc.modifyVmcardInfo(request);
            //}
            //else
            {
                string caption = "电子健康码个人信息修改";
                if (string.IsNullOrEmpty(request)) return string.Empty;
                Log.OutputXml(caption + ":\r\n" + request);
                string reqJson = string.Empty;
                try
                {
                    //encryptUrl = Function.ReadConfigXml("encryptUrl");
                    //decipheringUrl = Function.ReadConfigXml("decipheringUrl");
                    // string signUrl = Function.ReadConfigXml("signUrl");
                    //string apiUrl = Function.ReadConfigXml("apiUrl");
                    appId = ReadXmlConfig("appId");
                    key = ReadXmlConfig("key");
                    orgCode = ReadXmlConfig("orgCode");
                    appRecordNo = ReadXmlConfig("appRecordNo");
                    EntityRes01 resVo = null;
                    Dictionary<string, string> dic = Function.ReadXmlNodes(request, "req");
                    string erhcCardNo = dic["erhcCardNo"].ToString();
                    string sex = dic["sex"].ToString();
                    string nation = dic["nation"].ToString();
                    string validStartdate = dic["validStartdate"].ToString();
                    string validEnddate = dic["validEnddate"].ToString();
                    string idInst = dic["idInst"].ToString();
                    string birthday = dic["birthday"].ToString();
                    string birthplace = dic["birthplace"].ToString();
                    string phone = dic["phone"].ToString();
                    if (!string.IsNullOrEmpty(phone))
                        phone = Encrypt(phone);

                    string linkman = dic["linkman"].ToString();
                    if (string.IsNullOrEmpty(linkman))
                        linkman = Encrypt(linkman);

                    string telephone = dic["telephone"].ToString();
                    if (string.IsNullOrEmpty(telephone))
                        telephone = Encrypt(telephone);
                    string address = dic["address"].ToString();
                    string currentAddress = dic["currentAddress"].ToString();
                    string maritalstatuscode = dic["maritalstatuscode"].ToString();
                    string idPhoto = dic["idPhoto"].ToString();
                    string scenePhoto = dic["scenePhoto"].ToString();
                    string nationality = dic["nationality"].ToString();
                    string language = dic["language"].ToString();
                    string appMode = dic["appMode"].ToString();

                    //时间戳
                    string timestamp = GetTimeStamp();
                    timestamp = Encrypt(timestamp);

                    string nonceStr = "1234567890";
                    string bodySign = string.Empty;
                    string headSign = string.Empty;

                    //头部签名
                    string headJson = string.Empty;
                    headJson += "{";
                    headJson += string.Format("\"key\": \"{0}\",", key);
                    headJson += "\"mode\":\"SM3\",";
                    headJson += "\"body\":{";
                    headJson += string.Format("\"appId\":\"{0}\",", appId);
                    headJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr);
                    headJson += string.Format("\"timestamp\":\"{0}\",", timestamp);
                    headJson += "\"version\":\"V2.0.0\"";
                    headJson += "}";
                    headJson += "}";
                    resVo = Sm3Sign(headJson);
                    if (resVo != null)
                        headSign = resVo.result;

                    //数据签名
                    string bodyJson = string.Empty;
                    bodyJson += "{";
                    bodyJson += string.Format("\"key\": \"{0}\",", key);
                    bodyJson += "\"mode\":\"SM3\",";
                    bodyJson += "\"body\":{ " + Environment.NewLine;
                    bodyJson += string.Format("\"erhcCardNo\":\"{0}\",", erhcCardNo) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(sex))
                        bodyJson += string.Format("\"sex\":\"{0}\",", sex) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(nation))
                        bodyJson += string.Format("\"nation\":\"{0}\",", nation) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(validStartdate))
                        bodyJson += string.Format("\"validStartdate\":\"{0}\",", validStartdate) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(validEnddate))
                        bodyJson += string.Format("\"validEnddate\":\"{0}\",", validEnddate) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(idInst))
                        bodyJson += string.Format("\"idInst\":\"{0}\",", idInst) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(birthday))
                        bodyJson += string.Format("\"birthday\":\"{0}\",", birthday) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(birthplace))
                        bodyJson += string.Format("\"birthplace\":\"{0}\",", birthplace) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(phone))
                        bodyJson += string.Format("\"phone\":\"{0}\",", phone) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(linkman))
                        bodyJson += string.Format("\"linkman\":\"{0}\",", linkman) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(telephone))
                        bodyJson += string.Format("\"telephone\":\"{0}\",", telephone) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(address))
                        bodyJson += string.Format("\"address\":\"{0}\",", address) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(currentAddress))
                        bodyJson += string.Format("\"currentAddress\":\"{0}\",", currentAddress) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(maritalstatuscode))
                        bodyJson += string.Format("\"maritalstatuscode\":\"{0}\",", maritalstatuscode) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(idPhoto))
                        bodyJson += string.Format("\"idPhoto\":\"{0}\",", idPhoto) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(scenePhoto))
                        bodyJson += string.Format("\"scenePhoto\":\"{0}\",", scenePhoto) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(nationality))
                        bodyJson += string.Format("\"nationality\":\"{0}\",", nationality) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(language))
                        bodyJson += string.Format("\"language\":\"{0}\",", language) + Environment.NewLine;
                    bodyJson += string.Format("\"appMode\":\"{0}\",", appMode) + Environment.NewLine;
                    bodyJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    bodyJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    bodyJson += "}" + Environment.NewLine;
                    bodyJson += "}";
                    resVo = Sm3Sign(bodyJson);
                    if (resVo != null)
                        bodySign = resVo.result;

                    //请求报文
                    reqJson += "{" + Environment.NewLine;
                    reqJson += "\"method\":\"modifyVmcardInfo\"," + Environment.NewLine;
                    reqJson += string.Format("\"headSign\":\"{0}\",", headSign) + Environment.NewLine;
                    reqJson += string.Format("\"bodySign\":\"{0}\",", bodySign) + Environment.NewLine;
                    reqJson += "\"version\":\"V2.0.0\"," + Environment.NewLine;
                    reqJson += string.Format("\"appId\":\"{0}\",", appId) + Environment.NewLine;
                    reqJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr) + Environment.NewLine;
                    reqJson += string.Format("\"timestamp\":\"{0}\",", timestamp) + Environment.NewLine;
                    reqJson += "\"signMode\":\"SM3\"," + Environment.NewLine;
                    reqJson += "\"encryptMode\":\"SM4/ECB/ZeroBytePadding\"," + Environment.NewLine;
                    reqJson += "\"body\":{ " + Environment.NewLine;
                    reqJson += string.Format("\"erhcCardNo\":\"{0}\",", erhcCardNo) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(sex))
                        reqJson += string.Format("\"sex\":\"{0}\",", sex) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(nation))
                        reqJson += string.Format("\"nation\":\"{0}\",", nation) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(validStartdate))
                        reqJson += string.Format("\"validStartdate\":\"{0}\",", validStartdate) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(validEnddate))
                        reqJson += string.Format("\"validEnddate\":\"{0}\",", validEnddate) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(idInst))
                        reqJson += string.Format("\"idInst\":\"{0}\",", idInst) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(birthday))
                        reqJson += string.Format("\"birthday\":\"{0}\",", birthday) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(birthplace))
                        reqJson += string.Format("\"birthplace\":\"{0}\",", birthplace) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(phone))
                        reqJson += string.Format("\"phone\":\"{0}\",", phone) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(linkman))
                        reqJson += string.Format("\"linkman\":\"{0}\",", linkman) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(telephone))
                        reqJson += string.Format("\"telephone\":\"{0}\",", telephone) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(address))
                        reqJson += string.Format("\"address\":\"{0}\",", address) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(currentAddress))
                        reqJson += string.Format("\"currentAddress\":\"{0}\",", currentAddress) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(maritalstatuscode))
                        reqJson += string.Format("\"maritalstatuscode\":\"{0}\",", maritalstatuscode) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(idPhoto))
                        reqJson += string.Format("\"idPhoto\":\"{0}\",", idPhoto) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(scenePhoto))
                        reqJson += string.Format("\"scenePhoto\":\"{0}\",", scenePhoto) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(nationality))
                        reqJson += string.Format("\"nationality\":\"{0}\",", nationality) + Environment.NewLine;
                    if (!string.IsNullOrEmpty(language))
                        reqJson += string.Format("\"language\":\"{0}\",", language) + Environment.NewLine;
                    reqJson += string.Format("\"appMode\":\"{0}\",", appMode) + Environment.NewLine;
                    reqJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    reqJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    reqJson += "}" + Environment.NewLine;
                    reqJson += "}";

                    Log.Output(reqJson);
                    response = httpPost(reqJson);
                    Log.Output(response);
                    //if (!string.IsNullOrEmpty(response))
                    //{
                    //    XmlDocument doc = JsonHelper.Json2Xml(response);
                    //    response = doc.OuterXml.ToString().Replace("<?xml version=\"1.0\" encoding=\"gb2312\" standalone=\"yes\"?>", " ");
                    //}
                }
                catch (Exception ex)
                {
                    Log.OutputXml(caption + ":\r\n" + ex.Message);
                }
            }
            
            return response;
        }
        #endregion

        #region 6.3	电子健康码个人信息查询
        /// <summary>
        /// 6.3	电子健康码个人信息查询
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [WebMethod]
        public string getPersonInfo(string request)
        {
            string response = string.Empty;
            //proxy = Function.Int(ReadXmlConfig("proxy"));
            //if (proxy == 1)
            //{
            //    hyCodeService svc = new hyCodeService();
            //    response = svc.getPersonInfo(request);
            //}
            //else
            {
                appId = ReadXmlConfig("appId");
                key = ReadXmlConfig("key");
                orgCode = ReadXmlConfig("orgCode");
                appRecordNo = ReadXmlConfig("appRecordNo");

                string caption = "电子健康码个人信息查询";
                if (string.IsNullOrEmpty(request)) return string.Empty;
                Log.OutputXml(caption + ":\r\n" + request);
                string reqJson = string.Empty;
                try
                {
                    //request = @"<req><idCardTypeCode>01</idCardTypeCode><idCode>452502196502083620</idCode><appMode>2</appMode></req>";
                    EntityRes01 resVo = null;
                    Dictionary<string, string> dic = Function.ReadXmlNodes(request, "req");
                    string idCardTypeCode = dic["idCardTypeCode"].ToString();
                    string idCode = dic["idCode"].ToString();
                    string appMode = dic["appMode"].ToString();
                    //加密
                    idCode = Encrypt(idCode);

                    //时间戳
                    string timestamp = GetTimeStamp();
                    timestamp = Encrypt(timestamp);

                    string nonceStr = "1234567890";
                    string bodySign = string.Empty;
                    string headSign = string.Empty;

                    //头部签名
                    string headJson = string.Empty;
                    headJson += "{";
                    headJson += string.Format("\"key\": \"{0}\",", key);
                    headJson += "\"mode\":\"SM3\",";
                    headJson += "\"body\":{";
                    headJson += string.Format("\"appId\":\"{0}\",", appId);
                    headJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr);
                    headJson += string.Format("\"timestamp\":\"{0}\",", timestamp);
                    headJson += "\"version\":\"V2.0.0\"";
                    headJson += "}";
                    headJson += "}";
                    resVo = Sm3Sign(headJson);
                    if (resVo != null)
                        headSign = resVo.result;

                    //数据签名
                    string bodyJson = string.Empty;
                    bodyJson += "{";
                    bodyJson += string.Format("\"key\": \"{0}\",", key);
                    bodyJson += "\"mode\":\"SM3\",";
                    bodyJson += "\"body\":{ ";
                    bodyJson += string.Format("\"idCardTypeCode\":\"{0}\",", idCardTypeCode);
                    bodyJson += string.Format("\"idCode\":\"{0}\",", idCode);
                    bodyJson += string.Format("\"appMode\":\"{0}\",", appMode);
                    bodyJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    bodyJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    bodyJson += "}" + Environment.NewLine;
                    bodyJson += "}";
                    resVo = Sm3Sign(bodyJson);
                    if (resVo != null)
                        bodySign = resVo.result;

                    //请求报文
                    reqJson += "{" + Environment.NewLine;
                    reqJson += "\"method\":\"getPersonInfo\"," + Environment.NewLine;
                    reqJson += string.Format("\"headSign\":\"{0}\",", headSign) + Environment.NewLine;
                    reqJson += string.Format("\"bodySign\":\"{0}\",", bodySign) + Environment.NewLine;
                    reqJson += "\"version\":\"V2.0.0\"," + Environment.NewLine;
                    reqJson += string.Format("\"appId\":\"{0}\",", appId) + Environment.NewLine;
                    reqJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr) + Environment.NewLine;
                    reqJson += string.Format("\"timestamp\":\"{0}\",", timestamp) + Environment.NewLine;
                    reqJson += "\"signMode\":\"SM3\"," + Environment.NewLine;
                    reqJson += "\"encryptMode\":\"SM4/ECB/ZeroBytePadding\"," + Environment.NewLine;
                    reqJson += "\"body\":{ " + Environment.NewLine;
                    reqJson += string.Format("\"idCardTypeCode\":\"{0}\",", idCardTypeCode) + Environment.NewLine;
                    reqJson += string.Format("\"idCode\":\"{0}\",", idCode) + Environment.NewLine;
                    reqJson += string.Format("\"appMode\":\"{0}\",", appMode) + Environment.NewLine;
                    reqJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    reqJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    reqJson += "}" + Environment.NewLine;
                    reqJson += "}";
                    Log.Output(reqJson);

                    response = httpPost(reqJson);

                    Log.Output(response);
                    //if (!string.IsNullOrEmpty(response))
                    //{
                    //    XmlDocument doc = JsonHelper.Json2Xml(response);
                    //    response = doc.OuterXml.ToString().Replace("<?xml version=\"1.0\" encoding=\"gb2312\" standalone=\"yes\"?>", " ") ;
                    //}
                }
                catch (Exception ex)
                {
                    Log.OutputXml(caption + ":\r\n" + ex.Message);
                }
            }

            return response;
        }
        #endregion

        #region 6.4	电子健康码二维码获取
        /// <summary>
        /// 6.4	电子健康码二维码获取
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [WebMethod]
        public string getActiveQrCode(string request)
        {
            string response = string.Empty;
            //proxy = Function.Int(ReadXmlConfig("proxy"));
            //if (proxy == 1)
            //{
            //    hyCodeService svc = new hyCodeService();
            //    response = svc.getActiveQrCode(request);
            //}
            //else
            {
                appId = ReadXmlConfig("appId");
                key = ReadXmlConfig("key");
                orgCode = ReadXmlConfig("orgCode");
                appRecordNo = ReadXmlConfig("appRecordNo");
                string caption = "电子健康码二维码获取";
                if (string.IsNullOrEmpty(request)) return string.Empty;
                Log.OutputXml(caption + ":\r\n" + request);

                string reqJson = string.Empty;
                try
                {
                    EntityRes01 resVo = null;
                    Dictionary<string, string> dic = Function.ReadXmlNodes(request, "req");
                    string erhcCardNo = dic["erhcCardNo"].ToString();
                    string appMode = dic["appMode"].ToString();
                    //时间戳
                    string timestamp = GetTimeStamp();
                    timestamp = Encrypt(timestamp);

                    string nonceStr = "1234567890";
                    string bodySign = string.Empty;
                    string headSign = string.Empty;

                    //头部签名
                    string headJson = string.Empty;
                    headJson += "{";
                    headJson += string.Format("\"key\": \"{0}\",", key);
                    headJson += "\"mode\":\"SM3\",";
                    headJson += "\"body\":{";
                    headJson += string.Format("\"appId\":\"{0}\",", appId);
                    headJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr);
                    headJson += string.Format("\"timestamp\":\"{0}\",", timestamp);
                    headJson += "\"version\":\"V2.0.0\"";
                    headJson += "}";
                    headJson += "}";
                    resVo = Sm3Sign(headJson);
                    if (resVo != null)
                        headSign = resVo.result;

                    //数据签名
                    string bodyJson = string.Empty;
                    bodyJson += "{";
                    bodyJson += string.Format("\"key\": \"{0}\",", key);
                    bodyJson += "\"mode\":\"SM3\",";
                    bodyJson += "\"body\":{ ";
                    bodyJson += string.Format("\"erhcCardNo\":\"{0}\",", erhcCardNo);
                    bodyJson += string.Format("\"appMode\":\"{0}\",", appMode);
                    bodyJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    bodyJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    bodyJson += "}" + Environment.NewLine;
                    bodyJson += "}";
                    resVo = Sm3Sign(bodyJson);
                    if (resVo != null)
                        bodySign = resVo.result;

                    //请求报文
                    reqJson += "{" + Environment.NewLine;
                    reqJson += "\"method\":\"getActiveQrCode\"," + Environment.NewLine;
                    reqJson += string.Format("\"headSign\":\"{0}\",", headSign) + Environment.NewLine;
                    reqJson += string.Format("\"bodySign\":\"{0}\",", bodySign) + Environment.NewLine;
                    reqJson += "\"version\":\"V2.0.0\"," + Environment.NewLine;
                    reqJson += string.Format("\"appId\":\"{0}\",", appId) + Environment.NewLine;
                    reqJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr) + Environment.NewLine;
                    reqJson += string.Format("\"timestamp\":\"{0}\",", timestamp) + Environment.NewLine;
                    reqJson += "\"signMode\":\"SM3\"," + Environment.NewLine;
                    reqJson += "\"encryptMode\":\"SM4/ECB/ZeroBytePadding\"," + Environment.NewLine;
                    reqJson += "\"body\":{ " + Environment.NewLine;
                    reqJson += string.Format("\"erhcCardNo\":\"{0}\",", erhcCardNo) + Environment.NewLine;
                    reqJson += string.Format("\"appMode\":\"{0}\",", appMode) + Environment.NewLine;
                    reqJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    reqJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    reqJson += "}" + Environment.NewLine;
                    reqJson += "}";
                    Log.Output(reqJson);
                    response = httpPost(reqJson);
                    Log.Output(response);
                    //if (!string.IsNullOrEmpty(response))
                    //{
                    //    XmlDocument doc = JsonHelper.Json2Xml(response);
                    //    response = doc.OuterXml.ToString().Replace("<?xml version=\"1.0\" encoding=\"gb2312\" standalone=\"yes\"?>", " ");
                    //}
                }
                catch (Exception ex)
                {
                    Log.OutputXml(caption + ":\r\n" + ex.Message);
                }
            }
            return response;
        }
        #endregion

        #region 6.5	电子卡二维码验证
        /// <summary>
        /// 6.5	电子卡二维码验证
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [WebMethod]
        public string getPersonInfoByQrCode(string request)
        {
            string response = string.Empty;
           // proxy = Function.Int(ReadXmlConfig("proxy"));
            //if (proxy == 1)
            //{
            //    hyCodeService svc = new hyCodeService();
            //    response = svc.getPersonInfoByQrCode(request);
            //}
            //else
            {
                //encryptUrl = Function.ReadConfigXml("encryptUrl");
                //decipheringUrl = Function.ReadConfigXml("decipheringUrl");
                // string signUrl = Function.ReadConfigXml("signUrl");
                //string apiUrl = Function.ReadConfigXml("apiUrl");
                appId = ReadXmlConfig("appId");
                key = ReadXmlConfig("key");
                orgCode = ReadXmlConfig("orgCode");
                appRecordNo = ReadXmlConfig("appRecordNo");
                string caption = "电子卡二维码验证";
                if (string.IsNullOrEmpty(request)) return string.Empty;
                Log.OutputXml(caption + ":\r\n" + request);
                string reqJson = string.Empty;
                try
                {
                    EntityRes01 resVo = null;
                    Dictionary<string, string> dic = Function.ReadXmlNodes(request, "req");
                    string qrCode = dic["qrCode"].ToString();
                    string terminalCode = ReadXmlConfig("terminalCode");//dic["terminalCode"].ToString();
                    string medStepCode = dic["medStepCode"].ToString();
                    string appMode = ReadXmlConfig("appMode");//dic["appMode"].ToString();
                    //时间戳
                    string timestamp = GetTimeStamp();
                    timestamp = Encrypt(timestamp);

                    string nonceStr = "1234567890";
                    string bodySign = string.Empty;
                    string headSign = string.Empty;

                    //头部签名
                    string headJson = string.Empty;
                    headJson += "{";
                    headJson += string.Format("\"key\": \"{0}\",", key);
                    headJson += "\"mode\":\"SM3\",";
                    headJson += "\"body\":{";
                    headJson += string.Format("\"appId\":\"{0}\",", appId);
                    headJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr);
                    headJson += string.Format("\"timestamp\":\"{0}\",", timestamp);
                    headJson += "\"version\":\"V2.0.0\"";
                    headJson += "}";
                    headJson += "}";
                    resVo = Sm3Sign(headJson);
                    if (resVo != null)
                        headSign = resVo.result;

                    //数据签名
                    string bodyJson = string.Empty;
                    bodyJson += "{";
                    bodyJson += string.Format("\"key\": \"{0}\",", key);
                    bodyJson += "\"mode\":\"SM3\",";
                    bodyJson += "\"body\":{ ";
                    bodyJson += string.Format("\"qrCode\":\"{0}\",", qrCode);
                    bodyJson += string.Format("\"terminalCode\":\"{0}\",", terminalCode);
                    bodyJson += string.Format("\"medStepCode\":\"{0}\",", medStepCode);
                    bodyJson += string.Format("\"appMode\":\"{0}\",", appMode);
                    bodyJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    bodyJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    bodyJson += "}" + Environment.NewLine;
                    bodyJson += "}";
                    resVo = Sm3Sign(bodyJson);
                    if (resVo != null)
                        bodySign = resVo.result;

                    //请求报文
                    reqJson += "{" + Environment.NewLine;
                    reqJson += "\"method\":\"getPersonInfoByQrCode\"," + Environment.NewLine;
                    reqJson += string.Format("\"headSign\":\"{0}\",", headSign) + Environment.NewLine;
                    reqJson += string.Format("\"bodySign\":\"{0}\",", bodySign) + Environment.NewLine;
                    reqJson += "\"version\":\"V2.0.0\"," + Environment.NewLine;
                    reqJson += string.Format("\"appId\":\"{0}\",", appId) + Environment.NewLine;
                    reqJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr) + Environment.NewLine;
                    reqJson += string.Format("\"timestamp\":\"{0}\",", timestamp) + Environment.NewLine;
                    reqJson += "\"signMode\":\"SM3\"," + Environment.NewLine;
                    reqJson += "\"encryptMode\":\"SM4/ECB/ZeroBytePadding\"," + Environment.NewLine;
                    reqJson += "\"body\":{ " + Environment.NewLine;
                    reqJson += string.Format("\"qrCode\":\"{0}\",", qrCode) + Environment.NewLine;
                    reqJson += string.Format("\"terminalCode\":\"{0}\",", terminalCode) + Environment.NewLine;
                    reqJson += string.Format("\"medStepCode\":\"{0}\",", medStepCode) + Environment.NewLine;
                    reqJson += string.Format("\"appMode\":\"{0}\",", appMode) + Environment.NewLine;
                    reqJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    reqJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    reqJson += "}" + Environment.NewLine;
                    reqJson += "}";
                    Log.Output(reqJson);

                    response = httpPost(reqJson);

                    Log.Output(response);
                    //if (!string.IsNullOrEmpty(response))
                    //{
                    //    XmlDocument doc = JsonHelper.Json2Xml(response);
                    //    response = doc.OuterXml.ToString().Replace("<?xml version=\"1.0\" encoding=\"gb2312\" standalone=\"yes\"?>", " ");
                    //}
                }
                catch (Exception ex)
                {
                    Log.OutputXml(caption + ":\r\n" + ex.Message);
                }
            }
            return response;
        }
        #endregion

        #region 6.6	查询账户是否注册
        /// <summary>
        /// 6.6	查询账户是否注册
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [WebMethod]
        public string queryIfHasRegistered(string request)
        {
            string response = string.Empty;
            //proxy = Function.Int(ReadXmlConfig("proxy"));
            //if (proxy == 1)
            //{
            //    hyCodeService svc = new hyCodeService();
            //    response = svc.queryIfHasRegistered(request);
            //}
            //else
            {
                appId = ReadXmlConfig("appId");
                key = ReadXmlConfig("key");
                orgCode = ReadXmlConfig("orgCode");
                appRecordNo = ReadXmlConfig("appRecordNo");
                string caption = "查询账户是否注册";
                if (string.IsNullOrEmpty(request)) return string.Empty;
                Log.OutputXml(caption + ":\r\n" + request);
                string reqJson = string.Empty;
                try
                {
                    EntityRes01 resVo = null;
                    Dictionary<string, string> dic = Function.ReadXmlNodes(request, "req");
                    string idCardTypeCode = dic["idCardTypeCode"].ToString();
                    string idCode = dic["idCode"].ToString();
                    string appMode = dic["appMode"].ToString();
                    //加密
                    idCode = Encrypt(idCode);

                    //时间戳
                    string timestamp = GetTimeStamp();
                    timestamp = Encrypt(timestamp);

                    string nonceStr = "1234567890";
                    string bodySign = string.Empty;
                    string headSign = string.Empty;

                    //头部签名
                    string headJson = string.Empty;
                    headJson += "{";
                    headJson += string.Format("\"key\": \"{0}\",", key);
                    headJson += "\"mode\":\"SM3\",";
                    headJson += "\"body\":{";
                    headJson += string.Format("\"appId\":\"{0}\",", appId);
                    headJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr);
                    headJson += string.Format("\"timestamp\":\"{0}\",", timestamp);
                    headJson += "\"version\":\"V2.0.0\"";
                    headJson += "}";
                    headJson += "}";
                    resVo = Sm3Sign(headJson);
                    if (resVo != null)
                        headSign = resVo.result;

                    //数据签名
                    string bodyJson = string.Empty;
                    bodyJson += "{";
                    bodyJson += string.Format("\"key\": \"{0}\",", key);
                    bodyJson += "\"mode\":\"SM3\",";
                    bodyJson += "\"body\":{ ";
                    bodyJson += string.Format("\"idCardTypeCode\":\"01\",", idCardTypeCode);
                    bodyJson += string.Format("\"idCode\":\"{0}\",", idCode);
                    bodyJson += string.Format("\"appMode\":\"{0}\",", appMode);
                    bodyJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    bodyJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    bodyJson += "}" + Environment.NewLine;
                    bodyJson += "}";
                    resVo = Sm3Sign(bodyJson);
                    if (resVo != null)
                        bodySign = resVo.result;

                    //请求报文
                    reqJson += "{" + Environment.NewLine;
                    reqJson += "\"method\":\"queryIfHasRegistered\"," + Environment.NewLine;
                    reqJson += string.Format("\"headSign\":\"{0}\",", headSign) + Environment.NewLine;
                    reqJson += string.Format("\"bodySign\":\"{0}\",", bodySign) + Environment.NewLine;
                    reqJson += "\"version\":\"V2.0.0\"," + Environment.NewLine;
                    reqJson += string.Format("\"appId\":\"{0}\",", appId) + Environment.NewLine;
                    reqJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr) + Environment.NewLine;
                    reqJson += string.Format("\"timestamp\":\"{0}\",", timestamp) + Environment.NewLine;
                    reqJson += "\"signMode\":\"SM3\"," + Environment.NewLine;
                    reqJson += "\"encryptMode\":\"SM4/ECB/ZeroBytePadding\"," + Environment.NewLine;
                    reqJson += "\"body\":{ " + Environment.NewLine;
                    reqJson += string.Format("\"idCardTypeCode\":\"{0}\",", idCardTypeCode) + Environment.NewLine;
                    reqJson += string.Format("\"idCode\":\"{0}\",", idCode) + Environment.NewLine;
                    reqJson += string.Format("\"appMode\":\"{0}\",", appMode) + Environment.NewLine;
                    reqJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    reqJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    reqJson += "}" + Environment.NewLine;
                    reqJson += "}";
                    Log.Output(reqJson);

                    response = httpPost(reqJson);
                    Log.Output(response);
                    //if (!string.IsNullOrEmpty(response))
                    //{
                    //    XmlDocument doc = JsonHelper.Json2Xml(response);
                    //    response = doc.OuterXml.ToString().Replace("<?xml version=\"1.0\" encoding=\"gb2312\" standalone=\"yes\"?>", " ");
                    //}
                }
                catch (Exception ex)
                {
                    Log.OutputXml(caption + ":\r\n" + ex.Message);
                }
            }
            return response;
        }
        #endregion

        #region 6.7	电子卡二维码领码/激活
        /// <summary>
        /// 6.7	电子卡二维码领码/激活
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [WebMethod]
        public string activateVmcardQRcode(string request)
        {
            string response = string.Empty;
           // proxy = Function.Int(ReadXmlConfig("proxy"));
            //if (proxy == 1)
            //{
            //    hyCodeService svc = new hyCodeService();
            //    response = svc.activateVmcardQRcode(request);
            //}
            //else
            {
                appId = ReadXmlConfig("appId");
                key = ReadXmlConfig("key");
                orgCode = ReadXmlConfig("orgCode");
                appRecordNo = ReadXmlConfig("appRecordNo");
                string caption = "电子卡二维码领码/激活";
                if (string.IsNullOrEmpty(request)) return string.Empty;
                Log.OutputXml(caption + ":\r\n" + request);

                string reqJson = string.Empty;
                try
                {
                    EntityRes01 resVo = null;
                    Dictionary<string, string> dic = Function.ReadXmlNodes(request, "req");
                    string idCardTypeCode = dic["idCardTypeCode"].ToString();
                    string idCode = dic["idCode"].ToString();
                    string appMode = dic["appMode"].ToString();
                    //加密
                    idCode = Encrypt(idCode);

                    //时间戳
                    string timestamp = GetTimeStamp();
                    timestamp = Encrypt(timestamp);

                    string nonceStr = "1234567890";
                    string bodySign = string.Empty;
                    string headSign = string.Empty;

                    //头部签名
                    string headJson = string.Empty;
                    headJson += "{";
                    headJson += string.Format("\"key\": \"{0}\",", key);
                    headJson += "\"mode\":\"SM3\",";
                    headJson += "\"body\":{";
                    headJson += string.Format("\"appId\":\"{0}\",", appId);
                    headJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr);
                    headJson += string.Format("\"timestamp\":\"{0}\",", timestamp);
                    headJson += "\"version\":\"V2.0.0\"";
                    headJson += "}";
                    headJson += "}";
                    resVo = Sm3Sign(headJson);
                    if (resVo != null)
                        headSign = resVo.result;

                    //数据签名
                    string bodyJson = string.Empty;
                    bodyJson += "{";
                    bodyJson += string.Format("\"key\": \"{0}\",", key);
                    bodyJson += "\"mode\":\"SM3\",";
                    bodyJson += "\"body\":{ ";
                    bodyJson += string.Format("\"idCardTypeCode\":\"01\",", idCardTypeCode);
                    bodyJson += string.Format("\"idCode\":\"{0}\",", idCode);
                    bodyJson += string.Format("\"appMode\":\"{0}\",", appMode);
                    bodyJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    bodyJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    bodyJson += "}" + Environment.NewLine;
                    bodyJson += "}";
                    resVo = Sm3Sign(bodyJson);
                    if (resVo != null)
                        bodySign = resVo.result;

                    //请求报文
                    reqJson += "{" + Environment.NewLine;
                    reqJson += "\"method\":\"activateVmcardQRcode\"," + Environment.NewLine;
                    reqJson += string.Format("\"headSign\":\"{0}\",", headSign) + Environment.NewLine;
                    reqJson += string.Format("\"bodySign\":\"{0}\",", bodySign) + Environment.NewLine;
                    reqJson += "\"version\":\"V2.0.0\"," + Environment.NewLine;
                    reqJson += string.Format("\"appId\":\"{0}\",", appId) + Environment.NewLine;
                    reqJson += string.Format("\"nonceStr\":\"{0}\",", nonceStr) + Environment.NewLine;
                    reqJson += string.Format("\"timestamp\":\"{0}\",", timestamp) + Environment.NewLine;
                    reqJson += "\"signMode\":\"SM3\"," + Environment.NewLine;
                    reqJson += "\"encryptMode\":\"SM4/ECB/ZeroBytePadding\"," + Environment.NewLine;
                    reqJson += "\"body\":{ " + Environment.NewLine;
                    reqJson += string.Format("\"idCardTypeCode\":\"{0}\",", idCardTypeCode) + Environment.NewLine;
                    reqJson += string.Format("\"idCode\":\"{0}\",", idCode) + Environment.NewLine;
                    reqJson += string.Format("\"appMode\":\"{0}\",", appMode) + Environment.NewLine;
                    reqJson += string.Format("\"orgCode\":\"{0}\",", orgCode) + Environment.NewLine;
                    reqJson += string.Format("\"appRecordNo\":\"{0}\"", appRecordNo) + Environment.NewLine;
                    reqJson += "}" + Environment.NewLine;
                    reqJson += "}";
                    Log.Output(reqJson);

                    response = httpPost(reqJson);
                    Log.Output(response);
                    //if (!string.IsNullOrEmpty(response))
                    //{
                    //    XmlDocument doc = JsonHelper.Json2Xml(response);
                    //    response = doc.OuterXml.ToString().Replace("<?xml version=\"1.0\" encoding=\"gb2312\" standalone=\"yes\"?>", " ");
                    //}
                }
                catch (Exception ex)
                {
                    Log.OutputXml(caption + ":\r\n" + ex.Message);
                }
            }

            return response;
        }
        #endregion

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [WebMethod]
        public string Encrypt(string request)
        {
            encryptUrl = ReadXmlConfig("encryptUrl");
            key = ReadXmlConfig("key");
           
            EntityRes01 resVo = new EntityRes01();
            string reqJson = string.Empty;
            reqJson += "{" + Environment.NewLine;
            reqJson += string.Format("\"key\":\"{0}\",",key) + Environment.NewLine;
            reqJson += string.Format("\"params\":\"{0}\",", request) + Environment.NewLine;
            reqJson += "\"mode\":\"SM4/ECB/ZeroBytePadding\"" + Environment.NewLine;
            reqJson += "}" + Environment.NewLine;

            //Log.Output(reqJson);
            string res = string.Empty;
            Encoding encoding = Encoding.GetEncoding("utf-8");
            byte[] dataArray = encoding.GetBytes(reqJson);

            // 创建请求
            HttpWebRequest httpWeb = (HttpWebRequest)HttpWebRequest.Create(encryptUrl);
            httpWeb.Method = "POST";
            httpWeb.ContentLength = dataArray.Length;
            httpWeb.ContentType = "application/json";       // "application/json"; 
            httpWeb.MediaType = "application/json";
            httpWeb.Accept = "application/json";
            // 创建输入流
            Stream dataStream = null;
            try
            {
                dataStream = httpWeb.GetRequestStream();
            }
            catch (WebException ex)
            {
                Log.Output(ex.Message);
                resVo.code = -1;
                resVo.message = "连接服务器失败";
                return resVo.result;//连接服务器失败
            }
            // 发送请求
            dataStream.Write(dataArray, 0, dataArray.Length);
            dataStream.Close();
            // 获取返回值
            try
            {
                HttpWebResponse response = (HttpWebResponse)httpWeb.GetResponse();
                StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
                string resp = reader.ReadToEnd();
                reader.Close();
                // log.response
                //Log.Output(resp);
                res = resp;
                resVo = JsonHelper.DeserializeObject<EntityRes01>(resp);
            }
            catch (WebException ex)
            {
                Log.Output(ex.Message);
            }
            return resVo.result ;
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [WebMethod]
        public string DeEncrypt(string request)
        {
            decipheringUrl = ReadXmlConfig("decipheringUrl");
            key = ReadXmlConfig("key");

            EntityRes01 resVo = new EntityRes01();
            string reqJson = string.Empty;
            reqJson += "{" + Environment.NewLine;
            reqJson += string.Format("\"key\":\"{0}\",",key) + Environment.NewLine;
            reqJson += string.Format("\"params\":\"{0}\",", request) + Environment.NewLine;
            reqJson += "\"mode\":\"SM4/ECB/ZeroBytePadding\"" + Environment.NewLine;
            reqJson += "}" + Environment.NewLine;
            //Log.Output(reqJson);
            string res = string.Empty;
            Encoding encoding = Encoding.GetEncoding("utf-8");
            byte[] dataArray = encoding.GetBytes(reqJson);
            // 创建请求
            HttpWebRequest httpWeb = (HttpWebRequest)HttpWebRequest.Create(decipheringUrl);
            httpWeb.Method = "POST";
            httpWeb.ContentLength = dataArray.Length;
            httpWeb.ContentType = "application/json";       // "application/json"; 
            httpWeb.MediaType = "application/json";
            httpWeb.Accept = "application/json";
            // 创建输入流
            Stream dataStream = null;
            try
            {
                dataStream = httpWeb.GetRequestStream();
            }
            catch (WebException ex)
            {
                Log.Output(ex.Message);
                resVo.code = -1;
                resVo.message = "连接服务器失败";
                return resVo.result;//连接服务器失败
            }
            // 发送请求
            dataStream.Write(dataArray, 0, dataArray.Length);
            dataStream.Close();
            // 获取返回值
            try
            {
                HttpWebResponse response = (HttpWebResponse)httpWeb.GetResponse();
                StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
                string resp = reader.ReadToEnd();
                reader.Close();
                // log.response
                //Log.Output(resp);
                res = resp;
                resVo = JsonHelper.DeserializeObject<EntityRes01>(resp);
            }
            catch (WebException ex)
            {
                Log.Output(ex.Message);
            }
            return resVo.result;
        }
        
        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public EntityRes01 Sm3Sign(string request)
        {
            //request += "{";
            //request += "\"key\": \"F2D8D966CD3D47788449C19D5EF2081B\",";
            //request += "\"mode\":\"SM3\",";
            //request += "\"body\":{";
            //request += "\"appId\":\"60C90F3B796B41878B8D9C393E2B6329\",";
            //request += "\"nonceStr\":\".88357776802397576516672734238763958247\",";
            //request += "\"orgCode\":\"LDWLYXGS\",";
            //request += "\"timestamp\":\"1541816252.000000000000000000000000000004\",";
            //request += "\"version\":\"V1.0.2\"";
            //request += "}";
            //request += "}";
            signUrl = ReadXmlConfig("signUrl");
            EntityRes01 resVo = new EntityRes01();
            if (string.IsNullOrEmpty(request))
                return null;
            string res = string.Empty;
            Encoding encoding = Encoding.GetEncoding("utf-8");
            byte[] dataArray = encoding.GetBytes(request);
            // 创建请求
            HttpWebRequest httpWeb = (HttpWebRequest)HttpWebRequest.Create(signUrl);
            httpWeb.Method = "POST";
            httpWeb.ContentLength = dataArray.Length;
            httpWeb.ContentType = "application/json";       // "application/json"; 
            httpWeb.MediaType = "application/json";
            httpWeb.Accept = "application/json";
            // 创建输入流
            Stream dataStream = null;
            try
            {
                dataStream = httpWeb.GetRequestStream();
            }
            catch (WebException ex)
            {
                Log.Output(ex.Message);
                resVo.code = -1;
                resVo.message = "连接服务器失败";
                return resVo;//连接服务器失败
            }
            // 发送请求
            dataStream.Write(dataArray, 0, dataArray.Length);
            dataStream.Close();
            // 获取返回值
            try
            {
                HttpWebResponse response = (HttpWebResponse)httpWeb.GetResponse();
                StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
                string resp = reader.ReadToEnd();
                reader.Close();
                // log.response
                //Log.Output(resp);
                res = resp;
                resVo = JsonHelper.DeserializeObject<EntityRes01>(resp);
            }
            catch (WebException ex)
            {
                Log.Output(ex.Message);
            }
            return resVo;
        }
        
        /// <summary>
        /// 发送请求
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public string httpPost(string request)
        {
            string res = string.Empty;
            apiUrl = ReadXmlConfig("apiUrl");
            Encoding encoding = Encoding.GetEncoding("utf-8");
            byte[] dataArray = encoding.GetBytes(request);
            // 创建请求
            //Log.Output("apiUrl-->" + apiUrl);
            HttpWebRequest httpWeb = (HttpWebRequest)HttpWebRequest.Create(apiUrl);
            httpWeb.Method = "POST";
            httpWeb.ContentLength = dataArray.Length;
            httpWeb.ContentType = "application/json";       
            httpWeb.MediaType = "application/json";
            httpWeb.Accept = "application/json";
            // 创建输入流
            Stream dataStream = null;
            try
            {
                dataStream = httpWeb.GetRequestStream();
            }
            catch (WebException ex)
            {
                Log.Output(ex.Message);
                return res;//连接服务器失败
            }
            // 发送请求
            dataStream.Write(dataArray, 0, dataArray.Length);
            dataStream.Close();
            // 获取返回值
            try
            {
                HttpWebResponse response = (HttpWebResponse)httpWeb.GetResponse();
                StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
                string resp = reader.ReadToEnd();
                reader.Close();
                // log.response
                //Log.Output(resp);
                res = resp;
                //res = JsonConvert.DeserializeObject<EntityRes>(resp);
            }
            catch (WebException ex)
            {
                Log.Output(ex.Message);
            }
            return res;
        }

        /// <summary>
        /// 获取时间戳
        /// </summary>
        /// <returns></returns>
        
        public string GetTimeStamp()
        {
            TimeSpan ts = DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt32(ts.TotalSeconds).ToString();
        }

        #region 读配置文件
        /// <summary>
        /// 
        /// </summary>
        /// <param name="dbKey"></param>
        /// <returns></returns>
        public string ReadXmlConfig(string dbKey)
        {
            string result = null;
            string text = Server.MapPath("./") + "/Config.xml"; 
            if (!File.Exists(text))
            {
                try
                {
                    text = AppDomain.CurrentDomain.BaseDirectory + "\\bin\\Config.xml";
                    if (!File.Exists(text))
                    {
                        text = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\bin\\Config.xml";
                    }
                }
                catch (Exception ex)
                {
                    text = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\bin\\Config.xml";
                    ExceptionLog.OutPutException("ReadXmlConfig-->" + ex);
                }
            }
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.Load(text);
            XmlNodeList xmlNodeList = xmlDocument.SelectNodes("/configuration");
            XmlNodeList xmlNodeList2 = xmlNodeList[0].SelectNodes("Client");
            foreach (XmlNode xmlNode in xmlNodeList2)
            {
                foreach (XmlNode xmlNode2 in xmlNode.ChildNodes)
                {
                    if (xmlNode2.Name == dbKey)
                    {
                        result = xmlNode2.InnerText;
                    }
                }
            }
            return result;
        }
        #endregion

    }

    public class Log
    {
        public static void OutputXml(string xml)
        {
            bool isWrite = false;
            try
            {
                isWrite = true; //Function.Int(Function.ReadConfigXml("isOutXmlLog")) == 1 ? true : false;
            }
            catch
            {
                isWrite = false;
            }
            if (isWrite) Output(xml);
        }

        public static void OutputXml(string xml, bool isWrite)
        {
            if (isWrite) Output(xml);
        }

        public static void Output(string txt)
        {
            string strDate = DateTime.Now.ToString("yyyy-MM-dd");
            string strTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss:fff");
            string strFile = System.AppDomain.CurrentDomain.BaseDirectory + @"\log\" + strDate + ".txt";
            bool blnAllWaysNew = false;
            StreamWriter sw = null;
            try
            {
                FileInfo fi = new FileInfo(strFile);
                if (fi.Exists)
                {
                    if (fi.Length >= 2000000)
                    {
                        fi.CopyTo(System.AppDomain.CurrentDomain.BaseDirectory + @"\log\" + strDate + "-" + DateTime.Now.ToString("HHmm") + ".txt", true);
                        sw = fi.CreateText();
                    }
                    else
                    {
                        if (blnAllWaysNew)
                        {
                            sw = fi.CreateText();
                        }
                        else
                        {
                            sw = fi.AppendText();
                        }
                    }
                }
                else
                {
                    if (!Directory.Exists(fi.DirectoryName))
                    {
                        Directory.CreateDirectory(fi.DirectoryName);
                    }
                    sw = fi.CreateText();
                }
                sw.WriteLine("-->>>>> " + strTime);
                sw.WriteLine(txt);
                sw.WriteLine();
            }
            catch (Exception e)
            {
                //throw e;
            }
            finally
            {
                if (sw != null)
                {
                    sw.Close();
                }
            }
        }

        public static void Output(string fileName, string txt)
        {
            StreamWriter sw = null;
            try
            {
                FileInfo fi = new FileInfo(fileName);
                if (fi.Exists)
                {
                    sw = fi.AppendText();
                }
                else
                {
                    if (!Directory.Exists(fi.DirectoryName))
                    {
                        Directory.CreateDirectory(fi.DirectoryName);
                    }
                    sw = fi.CreateText();
                }
                sw.WriteLine(txt);
                sw.WriteLine();
            }
            catch (Exception e)
            {
                //throw e;
            }
            finally
            {
                if (sw != null)
                {
                    sw.Close();
                }
            }
        }


    }
}
