using HtmlAgilityPack;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using static System.Net.WebRequestMethods;
//此
public class VpnService : IDisposable
{ 
    private const string LoginAuthUrl = "https://webvpn.zju.edu.cn/por/login_auth.csp?apiversion=1";
    private const string LoginPswUrl = "https://webvpn.zju.edu.cn/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1";
    public bool IsVpnEnabled=false;
    public  HttpClient client;
    public CookieContainer Jar;
    private bool _disposed = false;
    public bool Logined = false;
    public bool AutoDirect = true;
    public Cookie TWFID => Jar.GetCookies(new Uri("https://webvpn.zju.edu.cn"))["TWFID"]??new Cookie();

    public VpnService()
    {
        Jar = new CookieContainer();
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = AutoDirect,
            CookieContainer = Jar,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            
        };

        client = new HttpClient(handler);
        client.DefaultRequestHeaders.Add("Referer", "https://webvpn.zju.edu.cn/portal/");
        client.DefaultRequestHeaders.Connection.ParseAdd("keep-alive");
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0");
    }

    public async Task<string> LoginAsync(string username, string password,CancellationToken cts=default)
    {
        var authResponse = await client.GetAsync(LoginAuthUrl);
        authResponse.EnsureSuccessStatusCode();
        var authXml = await authResponse.Content.ReadAsStringAsync();
        var (csrfRandCode, encryptKey, encryptExp) = ParseAuthXml(authXml);
        string encryptedPassword = EncryptPassword($"{password}_{csrfRandCode}", encryptKey, encryptExp);
        var formData = new Dictionary<string, string>
        {
            {"mitm_result", ""},
            {"svpn_req_randcode", csrfRandCode},
            {"svpn_name", username},
            {"svpn_password", encryptedPassword},
            {"svpn_rand_code", ""}
        };

        var content = new FormUrlEncodedContent(formData);
        var loginResponse = await client.PostAsync(LoginPswUrl, content);
        var loginXml = await loginResponse.Content.ReadAsStringAsync();
        if (VerifyLoginResult(loginXml) == "1")
        {
            Logined=true;
        }
        return VerifyLoginResult(loginXml);
       
    }

    private (string csrf, string key, string exp) ParseAuthXml(string xml)
    {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        var csrf = doc.SelectSingleNode("//CSRF_RAND_CODE")?.InnerText
            ?? throw new Exception("CSRF_RAND_CODE not found");
        var key = doc.SelectSingleNode("//RSA_ENCRYPT_KEY")?.InnerText
            ?? throw new Exception("RSA_ENCRYPT_KEY not found");
        var exp = doc.SelectSingleNode("//RSA_ENCRYPT_EXP")?.InnerText
            ?? throw new Exception("RSA_ENCRYPT_EXP not found");

        return (csrf, key, exp);
    }

    private string EncryptPassword(string plainText, string modulusHex, string exponentDec)
    {
        // 将十六进制字符串转换为字节数组
        byte[] modulus = HexStringToByteArray(modulusHex);
        byte[] exponent = DecimalToByteArray(exponentDec);//注意，webvpn返回十进制指数，而非10001.

        // 创建RSA参数
        var rsaParams = new RSAParameters
        {
            Modulus = modulus,
            Exponent = exponent
        };

        // 使用RSA加密
        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(rsaParams);

        byte[] data = Encoding.UTF8.GetBytes(plainText);
        byte[] encrypted = rsa.Encrypt(data, false);

        // 返回十六进制小写字符串
        return BitConverter.ToString(encrypted).Replace("-", "").ToLower();
    }

    private string VerifyLoginResult(string xml)
    {
        var doc = new XmlDocument();
        doc.LoadXml(xml);

        var result = doc.SelectSingleNode("//Result")?.InnerText;
        var message = doc.SelectSingleNode("//Message")?.InnerText ?? "Unknown error";

        if (result == "1")
        {
            return "1";
        }
        else
        {
            return $"400:{message}";
        }
           
        
    }
    public async Task<string> CheckNetwork(bool UseVpn,CancellationToken cts=default)
    {
        string Mirror_Url =  "https://mirrors.zju.edu.cn/api/is_campus_network";
        string target_uri = UseVpn ? ConvertUrl(Mirror_Url) : Mirror_Url;
        try
        {
            var response = await client.GetAsync(Mirror_Url);
            if (response.IsSuccessStatusCode)
            {
                string res_text = await response.Content.ReadAsStringAsync();
                if (res_text == "0")
                {
                    return "0";
                }
                else if (res_text == "1" || res_text == "2")
                {
                    return "1";
                }
                else
                {
                    return "404:非法返回";
                }
            }
            else
            {
                return "404:请求失败";
            }
        }
        catch (Exception ex)
        {
            return $"404:{ex.Message}";
        }
        

    }
    public async Task<byte[]> GetByteArrayAsync(string url, CancellationToken cts = default)
    {
        if (!Logined)
            throw new InvalidOperationException("Not logged in");

        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;
        try
        {
            var response = await client.GetAsync(targetUrl);
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsByteArrayAsync();
            }
        }
        catch { }
        return null;
        
    }
    public async Task<HttpResponseMessage> GetAsync(string url, bool webvpn = false,CancellationToken cts=default)
    {
        return await SendRequestAsync(HttpMethod.Get, url, null);
    }

    public async Task<HttpResponseMessage> PostAsync(string url, HttpContent content,CancellationToken cts=default)
    {
        return await SendRequestAsync(HttpMethod.Post, url,content);
    }
    public async Task<HttpResponseMessage> SendAsync(string url, HttpRequestMessage request, CancellationToken cts = default)
    {
        if (!Logined && IsVpnEnabled)
            throw new Exception("WebVPN未连接");
        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;
        request.RequestUri = new Uri(targetUrl);
        return await client.SendAsync(request);
    }
    public async Task<HttpResponseMessage> DeleteAsync(string url, CancellationToken cts = default)
    {
        if (!Logined && IsVpnEnabled)
            throw new Exception("WebVPN未连接");
        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;
        using var request = new HttpRequestMessage(HttpMethod.Delete,targetUrl);
        return await client.SendAsync(request);
    }
    public async Task<HttpResponseMessage> PutAsync(string url,StringContent content , CancellationToken cts = default)
    {
        if (!Logined && IsVpnEnabled)
            throw new Exception("WebVPN未连接");
        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;

        using var request = new HttpRequestMessage(HttpMethod.Put, targetUrl);
        request.Content = content;
        return await client.SendAsync(request);
    }
    private async Task<HttpResponseMessage> SendRequestAsync(HttpMethod method, string url,
        HttpContent content)
    {
        if (!Logined && IsVpnEnabled)
            throw new Exception("WebVPN未连接");

        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;

        using var request = new HttpRequestMessage(method, targetUrl);

        if (method == HttpMethod.Post && content != null)
        {
            request.Content = content;
        }

        var response = await client.SendAsync(request);


        return response;
    }

    public static string ConvertUrl(string originalUrl, CancellationToken cts = default)
    {
        var uri = new Uri(originalUrl);
        string hostname = uri.Host.Replace('.', '-');

        // 处理HTTPS
        if (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            hostname += "-s";

        // 处理非标准端口
        if (uri.Port > 0 &&
            !(uri.Scheme == "http" && uri.Port == 80) &&
            !(uri.Scheme == "https" && uri.Port == 443))
            hostname += $"-{uri.Port}-p";

        // 构建WebVPN URL
        return $"http://{hostname}.webvpn.zju.edu.cn:8001{uri.PathAndQuery}";
    }

    private static byte[] HexStringToByteArray(string hex)
    {
        // 确保十六进制字符串长度为偶数
        if (hex.Length % 2 != 0)
        {
            hex = "0" + hex; // 在开头添加0使长度变为偶数
        }

        int length = hex.Length;
        byte[] bytes = new byte[length / 2];

        for (int i = 0; i < length; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }

        return bytes;
    }
    public static byte[] DecimalToByteArray(string decimalNumber)
    {
        // 使用 BigInteger 处理大数
        BigInteger bigInt = BigInteger.Parse(decimalNumber);

        // 转换为字节数组
        byte[] byteArray = bigInt.ToByteArray();
        return byteArray;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                client?.Dispose();
            }
            _disposed = true;
        }
    }

}
