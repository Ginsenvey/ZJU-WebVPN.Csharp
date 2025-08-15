### ZJU WebVPN.Csharp

此脚本完全由[eWloYW8/ZJUWebVPN: A Python wrapper for accessing Zhejiang University WebVPN automatically. Compatible with requests.Session.](https://github.com/eWloYW8/ZJUWebVPN)翻译而成，实现以下功能：

- 登录浙江大学web vpn;

- 提供链接转写方法`ConvertUrl(string url)`.url必须具备scheme,比如http/https。

- 公开了属性`IsVpnEnabled`;`httpClient`;`Logined`;`TWFID`;`AutoDirect`,TWFID是鉴权的必要Cookie.公开了CancellationtokenSource `Cancellation`,提供一个默认的取消令牌源。如果想要自定义复杂取消方式，请修改源代码。

- 重写了Http请求的发送方法，比如Send/Get/Post/Put/Delete/GetBytesArray.当`IsVpnEnabled`为true且Logined为true时，请求均使用web vpn发送，同时自动改写Url。如果Logined为False,则报错弹出。登录失败返回“400：{错误信息}”。

**使用样例**

```csharp
var vpn=new VpnService();
string re=await vpn.LoginAsync("your_id","your_password");
if(re=="1")
{
    //在成功登录的情况下，才能安全地设置为true
    vpn.IsVpnEnabled=true;
    //发送请求
    var res=await vpn.GetAsync("https://www.cc98.org");
}

```
