from flask import Flask, request, Response, send_from_directory
from asoc import ASoC
from webhook_handler import WebhookHandler
from threading import Thread
import re
import sys
import os
import time
import json
import requests
import logging

#Create the log directory if it doesnt exit
if(not os.path.isdir("log")):
    #make the dir if it doesnt exist
    try:
        os.mkdir("log")
        if(not os.path.isdir("log")):
            print("Cannot make log directory! Exiting")
            sys.exit(1)
    except FileExistsError:
        print("Cannot make log directory! Exiting")
        sys.exit(1)

level = logging.INFO

#Setup Logging first
logger = logging.getLogger('asco_webhook_proxy')
logger.setLevel(level)
fh = logging.FileHandler('log/asco_webhook_proxy.log')
fh.setLevel(level)
ch = logging.StreamHandler()
ch.setLevel(level)
formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)

asoc = None
scriptDir = os.getcwd()
config = None
safePattern = None
reportBaseUrl = None
webhookHandler = None

"""
Initialize Globals
Validate Config
"""
def init():
    global asoc, config, safePattern, level, reportBaseUrl, webhookHandler
    
    logger.info("Initializing Web Hook Proxy")

    #Read the Config File config.json
    if(not os.path.isfile("config.json")):
        logger.error("Config (config.json) file doesn't exist! Exiting")
        sys.exit(1)
    try:
        with open("config.json") as f:
            config = json.load(f)
    except Exception as e:
        logger.error(e)
        logger.error("Cannot read config file! Bad Formatting? Exiting")
        sys.exit(1)
    
    logger.info("Config File Loaded")
    
    #Check to see if reports dir exists
    if(not os.path.isdir("reports")):
        #make the dir if it doesnt exist
        try:
            os.mkdir("reports")
            if(not os.path.isdir("reports")):
                logger.error("Cannot make report directory! Exiting")
                sys.exit(1)
        except FileExistsError:
            #File Exists Thats Ok
            pass
    logger.info("Reports Directory Exists")
    
    #Check to see if ASoC Creds Work
    apikey = config["asoc_api_key"]
    asoc = ASoC(config["asoc_api_key"])
    if(asoc.login()):
        logger.info("ASoC Credentials OK")
    else:
        logger.error("ASoC: Cannot login, check creds! Exiting")
        sys.exit(1)
    
    logger.info("Checking ASoC for Webhooks")
    reportBaseUrl = config["hostname"]+":"+str(config["port"])
    asocWebHooks = asoc.getWebhooks()
    if(asocWebHooks is not None):
        n = len(asocWebHooks)
        logger.info(f"{n} webhooks returned")
        for wh in config["webhooks"]:
            wh_name = wh["name"]
            calcConfigWHUrl = f"{reportBaseUrl}/asoc/{wh_name}"
            found = False
            for asocWh in asocWebHooks:
                calcAsocUrl = asocWh["Uri"].replace("/{SubjectId}", "")
                if(calcConfigWHUrl == calcAsocUrl):
                    found = True
            if(found):
                logger.info(f"Matched webhook [{wh_name}] in ASoC")
            else:
                logger.info(f"Webhook [{wh_name}] not found in ASoC.")
                logger.info(f"Attempting to create webhook in ASoC")
                if(asoc.createWebhook(wh["PresenceId"],calcConfigWHUrl+"/{SubjectId}"),True,None,wh["trigger"]):
                    logger.info(f"Successfully created ASoC Webhook [{wh_name}]")
                else:
                    logger.warning("Could not create ASoC Webhook... bad permissions?")
    safePattern = re.compile('[^a-zA-Z0-9\-_]')
    
    webhookHandler = WebhookHandler(asoc, config)
    logger.info("Created Webhook Handler Obj")
    
    logger.info("Initialization OK")
    
def getScanSummary(execId):
    global asoc
    if(not asoc.checkAuth()):
        if(not asoc.login()):
            logger.error("Cannot login, check network or credentials")
            return None
    scanExec = asoc.scanSummary(execId, True)
    if(not scanExec):
        logger.error(f"Error getting scan execution summary: {execId}")
        return None
    scanId = scanExec["ScanId"]
    scan = asoc.scanSummary(scanId)
    if(not scan):
        logger.error(f"Error getting scan summary: {scanId}")
        return None
    data = {
        "scan": scan,
        "scan_execution": scanExec
    }
    return data

def saveReport(execId, reportConfig, fullPath):
    if(not asoc.checkAuth()):
        if(not asoc.login()):
            logger.error("Cannot login, check network or credentials")
            return False
    reportId = asoc.startScanReport(execId, reportConfig, True)
    if(not reportId):
        logger.error("Error starting report for scan execution {execId}")
        return False
    waiting = asoc.waitForReport(reportId)
    if(not waiting):
        logger.error("Problem occurred waiting for report")
        return False
    if(not asoc.downloadReport(reportId, fullPath)):
        logger.error("Problem occurred downloading report")
        return False
    return True

"""
Function to translate the scan data to the format expected by
the webhook
"""
def scanDataToWebhookData(template, data, reportUrl=None):
    now = datetime.now()
    time_stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    app = data["scan"]["AppName"]
    scanFinishedRaw = data["scan_execution"]["ScanEndTime"]
    scanFinishedDt = datetime.strptime(scanFinishedRaw,"%Y-%m-%dT%H:%M:%S.%fZ")
    scanFinished = scanFinishedDt.strftime("%Y-%m-%d %H:%M:%S")
    duration_secs = data["scan_execution"]["ExecutionDurationSec"]
    duration_str = time.strftime('%Hh %Mm %Ss', time.gmtime(duration_secs))
    createdBy = data["scan_execution"]["CreatedBy"]["FirstName"]+" "
    createdBy += data["scan_execution"]["CreatedBy"]["LastName"]+" <"
    createdBy += data["scan_execution"]["CreatedBy"]["Email"]+">"
    scanName = data["scan"]["Name"]
    report_url = reportUrl
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
    if(not reportUrl):
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
        return None
    return templateJson
   

def processWebhook(webhook, execId, baseUrl):
    global scriptDir, config
    
    #Set the webhook fields
    webhookUrl = webhook["url"]
    webhookName = webhook["name"]
    reportConfig = webhook["report_config"]
    ext = reportConfig["Configuration"]["ReportFileType"].lower()
 
    #Build the real path to save the report file
    reportPath = f"{scriptDir}/reports/{execId}.{ext}"
    
    #Start pulling the scan summary from ASoC
    logger.info(f"Processing Webhook [{webhookName}] with scan execution [{execId}]")
    scandata = getScanSummary(execId)
    if(not scandata):
        return
    
    logger.info(f"[{webhookName}] Retrieved Scan Data Successfully")
    
    #Download the Report
    if(saveReport(execId, reportConfig, reportPath)):
        reportUrl = f"{baseUrl}/reports/{execId}.{ext}"
        logger.info(f"[{webhookName}] Calculated Report URL: {reportUrl}")
    else:
        reportUrl = None
    
    #Convert the scan data to the webhook template
    data = scanDataToWebhookData(f"templates/{webhookName}", scandata, reportUrl)
    
    if(data):
        logger.info(f"[{webhookName}] Translated Scan Data to Webhook Template")
    else:
        return
        
    #Make the webhook request
    result = postWebhook(webhookUrl, data)
    logger.info(f"[{webhookName}] Posted Data to Webhook, Response Code: {result}")
    
"""
Define Flask App (Lazy Mode)
"""
app = Flask(__name__)

#Catch webhook requests from ASoC
@app.route('/asoc/<webhook>/<execId>', methods=['GET'])
def respond(webhook, execId):
    global safePattern, config, reportBaseUrl, webhookHandler
    
    logger.info(f"Incoming Webook [{webhook}]")
    
    #Validate the request parameters
    validated = re.sub(safePattern, '', webhook)
    if(validated != webhook):
        logger.error("Invalid Chars in Webhook name. Valid = [a-Z0-9\-_]")
        return Response(status=400)
        
    validated = re.sub(safePattern, '', execId)
    if(validated != execId):
        logger.error("Invalid Chars in Scan Exec ID name. Valid = [a-Z0-9\-_]")
        return Response(status=400)
    
    #Map the incoming webhook to a WebhookObj in the config
    webhookObj = None
    for wh in config["webhooks"]:
        if(wh["name"] == webhook):
            webhookObj = wh
            break
            
    if(not webhookObj):
        logger.error(f"Cannot find webhook [{webhook}] in config file")
        return Response(status=400)
    
    logger.info(f"Matched webhook [{webhook}] from request to a configured WebHookObj")
    
    webhookType = None
    if(wh["type"]):
        webhookType = wh["type"]
    
    if(webhookType is None):
        logger.warning("No webhook type detected, assuming 'json_post'")
        webhookType = "json_post"
    
    logger.info(f"Webhook [{webhook}] has type [{webhookType}]")
    if(webhookType == "json_post"):
        #Ensure the webhook template exists
        template = wh["template"]
        if(not os.path.isfile(f"templates/{template}")):
            logger.error(f"Template {webhook} does not exist")
            return Response(status=400)
            
        
        logger.info(f"Verified the template exists for webhook [{webhook}]")
        logger.info(f"Sending [{webhook}] to handler")
        Thread(target=webhookHandler.handle, args=(webhook, execId)).start()
        return Response(status=202)
    elif(webhookType == "custom"):
        logger.info(f"Sending [{webhook}] to handler")
        Thread(target=webhookHandler.handleCustom, args=(webhook, execId)).start()
        return Response(status=202)
    else:
        logger.error("Invalid webhook type, expected json_post or custom")
        logger.info(f"Responding with 400")
        return Response(status=400)
        
    
    
    
    
    #Move the execution to a thread and respond immediately with 202 (Request Accepted)
    Thread(target=webhookHandler.handle, args=(webhook, execId)).start()
    return Response(status=202)

#Serve reports from the report directory
@app.route('/reports/<path:path>')
def sendreport(path):
    return send_from_directory('reports', path)
    
init()

