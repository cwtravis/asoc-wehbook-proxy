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
    
    for wh in config["webhooks"]["custom"]:
        wh_name = wh["name"]
        logger.info("Third party webhook [{wh_name}] Found")
        
    asocWebHooks = asoc.getWebhooks()
    if(asocWebHooks is not None):
        n = len(asocWebHooks)
        logger.info(f"{n} webhooks returned")
        for wh in config["webhooks"]["asoc"]:
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
Define Flask App (Lazy Mode)
"""
app = Flask(__name__)

"""
Catch webhook requests from ASoC
If the webhook comes from ASoC, then retrieve
Scan summary/App Data from ASoC API
"""
@app.route('/asoc/<webhook>/<id>', methods=['GET'])
def respond_asoc(webhook, id):
    global safePattern, config, reportBaseUrl, webhookHandler
    
    logger.info(f"Incoming Webook [{webhook}]")
    
    #Validate the request parameters
    validated = re.sub(safePattern, '', webhook)
    if(validated != webhook):
        logger.error("Invalid Chars in Webhook name. Valid = [a-Z0-9\-_]")
        return Response(status=400)
        
    validated = re.sub(safePattern, '', id)
    if(validated != id):
        logger.error("Invalid Chars in Scan Exec ID name. Valid = [a-Z0-9\-_]")
        return Response(status=400)
    
    #Map the incoming webhook to a WebhookObj in the config
    webhookObj = None
    for wh in config["webhooks"]["asoc"]:
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
        Thread(target=webhookHandler.handle, args=(wh, id)).start()
        return Response(status=202)
    else:
        logger.error("Invalid webhook type, Only json_post supported at this time.")
        logger.info(f"Responding with 400")
        return Response(status=400)

"""
Catch webhook requests from third party tools
Process any route that has
/<source>
Scan summary/App Data from ASoC API
"""
@app.route('/<source>', methods=['GET', 'POST'])
def process_custom(source):
    #Ignore if source is asoc
    if(source == "asoc"):
        Response(status=404)
    
    logger.info(f"Processing Custom Incoming Webhook  [{source}]")
    
    #Gather Data Submitted: Post Args, Query Args, Json Data
    if(len(request.args) == 0):
        queryArgs = None
    else:
        queryArgs = request.args
        
    if(len(request.form) == 0):
        postArgs = None
    else:
        postArgs = request.form
        
    jsonData = request.json
    
    data = {
        "query": queryArgs,
        "post": postArgs,
        "json": request.json
    }
    
    #Map the incoming webhook to a WebhookObj in the config
    webhookObj = None
    for wh in config["webhooks"]["custom"]:
        if(wh["name"] == source):
            webhookObj = wh
            break
    
    if(webhookObj is None):
        logger.error(f"No custom handler for webhook [{source}]") 
        return Response(status=400)
        
    Thread(target=webhookHandler.handleCustom, args=(webhookObj, data)).start()
    return Response(status=202)

#Serve static files from the report directory
@app.route('/reports/<path:path>')
def sendreport(path):
    return send_from_directory('reports', path)
    
init()

