
## AppScan on Cloud Webhook Proxy

This tool creates an endpoint for capturing AppScan on Cloud webhook requests, gathers additional data about the scan, creates a custom HTTP request based on a provided template, then reroutes it to the desired endpoints. By default, AppScan on Cloud only provides a scan execution ID to any listening endpoints. This scan execution ID needs to have further context to be useful, for alerting or reporting purposes. As an example, I have provided a template to create an alert message on a desired Discord channel. 

## Requirements

This tool was written for Python3 and was tested against 3.9.0. 
Packages in use that will need to be installed:
1. Flask - Web server routing
2. Python Requests - API calls to ASoC

Install on Windows
```
py -m pip install Flask
py -m pip install requests
```
Install on Linux (pip or pip3 depending on your setup)
```
pip3 install Flask
pip3 install requests
```

## Setup and run ASoC Webhook Proxy

The FLASK_ENV can be development or production. I use development while testing demonstrating.

### Windows

```
git clone https://github.com/cwtravis/asoc-wehbook-proxy.git
cd asoc-wehbook-proxy
set FLASK_APP=asoc_webhook_proxy
set FLASK_ENV=development
py -m flask run --host=0.0.0.0 --port=5000
```

### Linux
```
git clone https://github.com/cwtravis/asoc-wehbook-proxy.git
cd asoc-wehbook-proxy
export FLASK_APP=asoc_webhook_proxy
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000
```
Leave off the host to run on localhost 127.0.0.1 or leave off the port to run on the default port 5000. ASoC Webhook Proxy will read the config file and listen on the indicated endpoints for webhook requests from ASoC. 

## Prerequisites

The config.json file needs to contain the following (see example):
1. Hostname and port of the running server
2. ASoC API Key
	a. This Account needs permissions to create/view webhooks and have visibility to the AssetGroups in ASoC required to pull scan data. If this is global, be sure that the account has permissions to view ALL asset groups scans.
3. Webhook Data

A template file that matches the Name of the webhook in the config file. In my example I use Discord. There is a discord template in the templates directory and a webhook in the config file with name "discord". This is so that ASoC can make a webook request with route "/asoc/discord/scan-execution-id" and ASoC Webhook Proxy knows to use the discord template and match the webhook URL from the config file with the discord webhook.

ASoC Webhook Proxy will attempt to create a webhook in ASoC if one doesn't exist for one found in the config.json file.

## Template Fields
Check the discord example template to see the fields in action. 
| Field | Meaning |
|--|--|
| {app} | Scanned Application Name |
| {scan_finished_time} | Time the Scan Execution Finished |
| {report_url} | URL of the downloaded report |
| {NIssuesFound} | Number of issues found during the scan |
| {NHighIssues} | Number of high severity issues found during the scan |
| {NMediumIssues} | Number of medium severity issues found during the scan |
| {NLowIssues} | Number of low severity issues found during the scan |
| {scanName} | Name of the scan in ASoC |
| {duration_str} | Duration of the scan in 0h 0m 0s |
| {createdBy} | Name and email of user that created the scan |
| {time_stamp} | Timestamp of when the webhook was received |

## Discord Example

First rename or copy config_example.json to config.json. ASoC Webhook Proxy will look for the config.json file adjacent to it in the folder.

To setup your Discord server to receive webhooks, right click your server and select Server Settings > Integrations > View Webhooks > New Webhook. Give your webhook a name to post under, select an channel for it to post to, and optionally select an avatar image. 

![Discord Example 1](http://chillaspect.com/images/asoc_whp2.png)

Click "Copy Webhook URL" to copy the URL to your clipboard and paste into your config file in "url" under the "discord" webhook. Also update the following fields in the config file:
1. Add ASoC API Key
2. Update Hostname and Port
3. Add an AppScan Presence ID (must be an active Presence Id. 

Now run ASoC Webhook Proxy and verify that a webhook is either already found or created for the discord webhook. Run a scan and watch the output from the ASoC Webhook Proxy. You should see an alert from Discord.

![Discord Example 2](http://chillaspect.com/images/asoc_whp1.png)

## Other Info

 - ASOC Webhook Proxy will output its logs to /logs/asoc_webhook_proxy.log
 - ASoC Webhook Proxy will download and save a scan report to /reports/{scan_execution_id}.html
 - The Flask webserver will serve files in the reports directory.
 - This is meant as a Proof of Concept to demonstrate what can be done with webhooks.
 - Implement this at your own risk.
 - Feel free to create an issue here for any problems.
