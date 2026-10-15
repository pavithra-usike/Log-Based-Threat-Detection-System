import json,os,urllib.request,urllib.parse
class ThreatIntel:
    def __init__(self,local_path="iocs.json"):
        p=os.path.join(os.path.dirname(__file__),local_path)
        try:
            with open(p,encoding="utf-8") as f: self.iocs=json.load(f)
        except Exception: self.iocs={"malicious_ips":[]}
    def is_malicious_ip(self,ip): return ip in set(self.iocs.get("malicious_ips",[]))
    def lookup_ip(self,ip):
        d={"ip":ip,"local_ioc_match":self.is_malicious_ip(ip),"source":"Local IOC database"}
        key=os.getenv("ABUSEIPDB_API_KEY")
        if not key:
            d["abuseipdb"]="Not configured. Set ABUSEIPDB_API_KEY to enable online lookup."; return d
        url="https://api.abuseipdb.com/api/v2/check?"+urllib.parse.urlencode({"ipAddress":ip,"maxAgeInDays":90})
        req=urllib.request.Request(url,headers={"Accept":"application/json","Key":key})
        try:
            with urllib.request.urlopen(req,timeout=8) as r: d["abuseipdb"]=json.loads(r.read().decode()).get("data",{})
        except Exception as e: d["abuseipdb_error"]=str(e)
        return d
