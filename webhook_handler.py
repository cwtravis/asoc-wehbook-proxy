from datetime import datetime
import requests
import time
import logging
import json
import importlib

logger = logging.getLogger('asoc_webhook_proxy')

class WebhookHandler:
    asoc = None
    config = None
    
    def __init__(self, asoc, config):
        self.config = config
        self.asoc = asoc
    
    def collectSubjectData(self, subjectId):
        if(not self.asoc.checkAuth()):
            if(not self.asoc.login()):
                logger.error("Cannot login, check network or credentials")
                return None
        scanExec = self.asoc.scanSummary(subjectId, True)
        if(not scanExec):
            logger.error(f"Error getting scan execution summary: {subjectId}")
            return None
        scanId = scanExec["ScanId"]
        scan = self.asoc.scanSummary(scanId)
        if(not scan):
            logger.error(f"Error getting scan summary: {scanId}")
            return None
        data = {
            "scan": scan,
            "scan_execution": scanExec
        }
        return data
    
    def saveReport(self, id, reportConfig, fullPath, type = "ScanExecutionCompleted"):
        if(not self.asoc.checkAuth()):
            if(not self.asoc.login()):
                logger.error("Cannot login, check network or credentials")
                return False
        reportId = self.asoc.startReport(id, reportConfig, type)
        if(not reportId):
            logger.error("Error starting report for scan execution {id}")
            return False
        waiting = self.asoc.waitForReport(reportId)
        if(not waiting):
            logger.error("Problem occurred waiting for report")
            return False
        if(not self.asoc.downloadReport(reportId, fullPath)):
            logger.error("Problem occurred downloading report")
            return False
        return True
        
    def applyTemplate(self, template, data):
        now = datetime.now()
        time_stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        app = data["scan"]["AppName"]
        app_id = data["scan"]["AppId"]
        scan_id = data["scan"]["Id"]
        scanFinishedRaw = data["scan_execution"]["ScanEndTime"]
        scanFinishedRaw = scanFinishedRaw[:19]+"Z"
        scanFinishedDt = datetime.strptime(scanFinishedRaw,"%Y-%m-%dT%H:%M:%SZ")
        scanFinished = scanFinishedDt.strftime("%Y-%m-%d %H:%M:%S")
        duration_secs = data["scan_execution"]["ExecutionDurationSec"]
        duration_str = time.strftime('%Hh %Mm %Ss', time.gmtime(duration_secs))
        createdBy = data["scan_execution"]["CreatedBy"]["FirstName"]+" "
        createdBy += data["scan_execution"]["CreatedBy"]["LastName"]+" <"
        createdBy += data["scan_execution"]["CreatedBy"]["Email"]+">"
        scanName = data["scan"]["Name"]
        
        report_url = None
        if(data["report_url"]):
            report_url = data["report_url"]

        NIssuesFound = data["scan_execution"]["NIssuesFound"]
        NHighIssues = data["scan_execution"]["NHighIssues"]
        NMediumIssues = data["scan_execution"]["NMediumIssues"]
        NLowIssues = data["scan_execution"]["NLowIssues"]
        
        templateStr = ""
        try:
            with open(template, "r") as f:
                templateStr = f.read()
        except Exception as e:
            logger.error(f"Error reading template file {template}")
            logger.error(e)
            return None
            
        templateStr = templateStr.replace("{app}", app)
        templateStr = templateStr.replace("{scan_finished_time}", scanFinished)
        templateStr = templateStr.replace("{time_stamp}", time_stamp)
        templateStr = templateStr.replace("{duration_str}", duration_str)
        templateStr = templateStr.replace("{createdBy}", createdBy)
        templateStr = templateStr.replace("{scanName}", scanName)
        scan_url = f"https://cloud.appscan.com/main/myapps/{app_id}/scans/{scan_id}/scanOverview"
        templateStr = templateStr.replace("{scan_url}", scan_url)
        
        if(report_url is None):
            templateStr = templateStr.replace("{report_url}", "")
        else:
            templateStr = templateStr.replace("{report_url}", report_url)
            
        templateStr = templateStr.replace("{NIssuesFound}", str(NIssuesFound))
        templateStr = templateStr.replace("{NHighIssues}", str(NHighIssues))
        templateStr = templateStr.replace("{NMediumIssues}", str(NMediumIssues))
        templateStr = templateStr.replace("{NLowIssues}", str(NLowIssues))
        
        templateJson = None
        try:
            templateJson = json.loads(templateStr)
        except Exception as e:
            logger.error("Error parsing templateStr to Python Dict")
            logger.error(e)
            print(templateStr)
            return None
        return templateJson
    
    """
    Function to make the post request to the webhook
    """
    def postWebhook(self, webhookUrl, data):
        resp = requests.post(webhookUrl, json=data)
        return resp.status_code
    
    def handleCustom(self, webhookObj, data):
        moduleName = webhookObj["handler"]
        try:
            logger.info(f"Loading custom handler for [{moduleName}]")
            handler = importlib.import_module(f"handlers.{moduleName}")
            logger.info(f"Custom handler for [{moduleName}] Loaded")
            logger.info(f"Calling handle function in {moduleName}")
            handler.handle(webhookObj, data)
        except ModuleNotFoundError as e:
            logger.error("Error importing custom handler code {moduleName}")
            logger.error(e)
        
    def handle(self, webhookObj, subjectId, type="json_post"):
        webhookName = webhookObj["name"]
        logger.info(f"Handling Webhook Call {webhookName} {subjectId}")
        scanExec = None
        scanData = None
        appData = None
        reportUrl = None
        
        logger.info("Collecting Data from ASoC")
        
        trigger = webhookObj["trigger"]
        reportTargetId = subjectId
        #Webhook exists and has matched to a configured webhook
        if(trigger == "ScanExecutionCompleted"):
            logger.info("Getting Scan Summary from ASoC")
            scanExec = self.asoc.scanSummary(subjectId, True)
            if(not scanExec):
                logger.error(f"Error getting scan execution summary {subjectId}")
                return None
                
            scanData = self.asoc.scanSummary(scanExec["ScanId"])
            if(not scanData):
                scanId = scanExec["ScanId"]
                logger.error(f"Error getting scan summary {scanId}")
                return None
                
            appId = scanData["AppId"]
        elif(trigger == "ApplicationUpdated"):
            appId = subjectId
            reportTargetId = appId
        else:
            logger.error(f"Unknown Webhook Trigger [{trigger}]")
            return False
        
        logger.info("Getting App Data from ASoC")
        appData = self.asoc.getApplication(appId)
        
        reportData = None
        if(webhookObj["report_config"]):
            logger.info("Downloading Report")
            ext = webhookObj["report_config"]["Configuration"]["ReportFileType"].lower()
            reportUrl = self.config["hostname"]+":"+str(self.config["port"])+"/reports/"+subjectId+"."+ext
            path = "reports/"+subjectId+"."+ext
            logger.debug(path)
            if(not self.saveReport(reportTargetId, webhookObj["report_config"], path, trigger)):
                reportUrl = None
            logger.debug("Report Saved")
        data = {
            "scan_execution": scanExec,
            "scan": scanData,
            "app": appData,
            "report_url": reportUrl
        }
        print(data)
        if(type=="json_post"):
            logger.info("Processing template")
            templateJson = self.applyTemplate("templates/"+webhookObj["template"], data)
            logger.info("Submitting Webhook Json Post")
            status = self.postWebhook(webhookObj["url"], templateJson)
            logger.info(f"Submitted Json to Webhook - Response Code {status}")

        
        
        
        
        
        
        
        
        
        
        
        
        
        
        