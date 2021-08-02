import requests
import time
import logging
logger = logging.getLogger('asco_webhook_proxy')

class ASoC:
    def __init__(self, apikey):
        self.apikey = apikey
        self.token = ""
        
    def login(self):
        resp = requests.post("https://cloud.appscan.com/api/V2/Account/ApiKeyLogin", json=self.apikey)
        if(resp.status_code == 200):
            jsonObj = resp.json()
            self.token = jsonObj["Token"]
            logger.debug(f"ASoC Login Token: {self.token}")
            return True
        else:
            logger.debug(f"ASoC Login")
            self.logResponse(resp)
            return False
        
    def logout(self):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get("https://cloud.appscan.com/api/V2/Account/Logout", headers=headers)
        if(resp.status_code == 200):
            self.token = ""
            logger.debug(f"ASoC Logged Out")
            return True
        else:
            logger.debug(f"ASoC Logout")
            self.logResponse(resp)
            return False
        
    def checkAuth(self):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get("https://cloud.appscan.com/api/V2/Account/TenantInfo", headers=headers)
        return resp.status_code == 200
    
    def getApplication(self, id):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        
        resp = requests.get("https://cloud.appscan.com/api/V2/Apps/"+id, headers=headers)
        
        if(resp.status_code == 200):
            return resp.json()
        else:
            logger.debug(f"ASoC App Summary Error Response")
            self.logResponse(resp)
            return None
            
    def scanSummary(self, id, is_execution=False):
        if(is_execution):
            asoc_url = "https://cloud.appscan.com/api/v2/Scans/Execution/"
        else:
            asoc_url = "https://cloud.appscan.com/api/v2/Scans/"
        
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        
        resp = requests.get(asoc_url+id, headers=headers)
        
        if(resp.status_code == 200):
            return resp.json()
        else:
            logger.debug(f"ASoC Scan Summary")
            self.logResponse(resp)
            return None
        
    def startReport(self, id, reportConfig, type="ScanExecutionCompleted"):
    
        if(type == "ScanExecutionCompleted"):
            url = "https://cloud.appscan.com/api/v2/Reports/Security/ScanExecution/"+id
        elif(type == "scan"):
            url = "https://cloud.appscan.com/api/v2/Reports/Security/Scan/"+id
        elif(type == "ApplicationUpdated"):
            url = "https://cloud.appscan.com/api/v2/Reports/Security/Application/"+id
        else:
            logger.error(f"Unknown Report Scope [{type}]")
            return None
            
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.post(url, headers=headers, json=reportConfig)
        if(resp.status_code == 200):
            return resp.json()["Id"]
        else:
            logger.debug(f"ASoC startReport Error Response")
            self.logResponse(resp)
            return None
        
    def reportStatus(self, reportId):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get("https://cloud.appscan.com/api/V2/Reports/"+reportId, headers=headers)
        if(resp.status_code == 200):
            return resp.json()["Status"]
        else:
            logger.debug(f"ASoC Report Status")
            self.logResponse(resp)
            return "Abort"
            
    def waitForReport(self, reportId, intervalSecs=3, timeoutSecs=60):
        status = None
        elapsed = 0
        while status not in ["Abort","Ready"] or elapsed >= timeoutSecs:
            status = self.reportStatus(reportId)
            elapsed += intervalSecs
            time.sleep(intervalSecs)   
        return status == "Ready"
        
    def downloadReport(self, reportId, fullPath):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get("https://cloud.appscan.com/api/v2/Reports/Download/"+reportId, headers=headers)
        if(resp.status_code==200):
            report_bytes = resp.content
            with open(fullPath, "wb") as f:
                f.write(report_bytes)
            return True
        else:
            logger.debug(f"ASoC Download Report")
            self.logResponse(resp)
            return False
    
    def getWebhooks(self):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get("https://cloud.appscan.com/api/V2/Webhooks", headers=headers)
        if(resp.status_code==200):
            return resp.json()
        else:
            logger.debug(f"ASoC Get Webhooks")
            self.logResponse(resp)
            return False
            
    def createWebhook(self, presenceId, Uri, globalFlag=True, assetGroupId=None, event="ScanExecutionCompleted"):
        data = {}
        data["PresenceId"] = presenceId
        data["Uri"] = Uri
        if(globalFlag is not None):
            data["Global"] = globalFlag
        if(assetGroupId is not None):
            data["AssetGroupId"] = assetGroupId
        if(event is not None):
            data["Event"] = event
        
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.post("https://cloud.appscan.com/api/V2/Webhooks", headers=headers, json=data)
        if(resp.status_code==200):
            return True
        else:
            logger.debug(f"ASoC Get Webhooks")
            self.logResponse(resp)
            return False
    
    def logResponse(self, resp):
        logger.debug(f"ASoC Error Response: {resp.status_code}")
        logger.debug(resp.text)
        
    
    
        
        