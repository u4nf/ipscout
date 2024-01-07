from shodan import Shodan
from operator import itemgetter
import ipinfo
import json, pprint, requests, argparse, csv

#parse arguments
parser = argparse.ArgumentParser(description='A commandline tool to retrieve metadata about an IP from multiple sources.')
parser.add_argument('-i', type=str, default='8.8.8.8', help='The IP address to scout')
parser.add_argument('-o', type=str, help='JSON output file name')
args=parser.parse_args()

#set variables
ip = args.i
outfile = args.o
output = {}


def compileCreds():
    #Take creds from csv, populate global variables
    creds = []

    credsPath = './creds.csv'
    with open(credsPath, 'r') as infile:
        reader = csv.reader(infile)

        for row in reader:
            creds.append(row)

    #iterate over list, set index 0 as the variable name, index 1 as the value
    for i in creds:
    	globals()[i[0]] = i[1]
        

def getShodanOutput(ip):
	client = Shodan(APIshodan)

	try:
		output = client.host(ip)
	except:
		#account for no shadan data available

		details = {}
		details['ports'] = 'No Data Available'

		return details
	
	return output


def getIPInfoOutput(ip):
	#queries ipinfo, view all data with <print(details.all)>

	client = ipinfo.getHandler(APIipinfo)
	details = client.getDetails(ip)

	return details.all


def getVTOutput(ip):

	url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
	params = {'apikey':APIvt,'ip': ip}
	response = requests.get(url, params=params)

	return json.loads(response.text)


def reverseIPLookup(ip):
	#queries hackertarget for url list, returns list object

	urls = requests.get(f'https://api.hackertarget.com/reverseiplookup/?q={ip}').text
	urlList = urls.splitlines()

	return urlList


def getAbuseIPDBOutput(ip):
	# Defining the api-endpoint
	url = 'https://api.abuseipdb.com/api/v2/check'

	querystring = {
	    'ipAddress': ip,
	    'maxAgeInDays': '90'
	}

	headers = {
	    'Accept': 'application/json',
	    'Key': APIabused
	}

	response = requests.request(method='GET', url=url, headers=headers, params=querystring)

	return json.loads(response.text)


def getVpnapiOutput(ip):

	url = f'https://vpnapi.io/api/{ip}?key={APIVPN}'
	response = requests.request(method='GET', url=url)

	return json.loads(response.text)


def dictToJson(dictIn, outfile):
	# Convert dictionary <dictIn> to JSON and write to file <OUTFILE>

	with open(outfile, "w") as outputFile: 
		jsonObject = json.dumps(dictIn, indent = 4)
		outputFile.write(jsonObject)

		#return jsonObject


def getHistoricUrls(vtOutput):
	#compile list of historic Urls as reported by VirusTotal
	#returns dict

	if (len(vtOutput['resolutions']) > 0):
		historicUrls = []

		for i in vtOutput['resolutions']:
			historicUrls.append(i)

	#order by date desc
	historicUrls = sorted(historicUrls, key=itemgetter("last_resolved"), reverse=True)

	return historicUrls


def parseToOutput():
	#parses multiple sources into a single output object
	output['location'] = vpnapiOutput['location']
	output['location']['flagURL'] = ipinfoOutput['country_flag_url']
	output['network'] = vpnapiOutput['network']
	output['network']['isp'] = abuseIPDBOutput['data']['isp']
	output['network']['usageType'] = abuseIPDBOutput['data']['usageType']
	output['network']['domain'] = abuseIPDBOutput['data']['domain']
	output['network']['isVPN'] = vpnapiOutput['security']['vpn']
	output['network']['isTOR'] = vpnapiOutput['security']['tor']
	output['network']['isProxy'] = vpnapiOutput['security']['proxy']
	output['network']['isRelay'] = vpnapiOutput['security']['relay']
	output['ports'] = shodanOutput['ports']
	output['ip'] = vpnapiOutput['ip']
	output['historicURLs'] = historicUrls
	output['vtDetections'] = vtOutput['detected_urls']
	output['abuseIPDBDetections'] = {}
	output['abuseIPDBDetections']['totalReports'] = abuseIPDBOutput['data']['totalReports']
	output['abuseIPDBDetections']['lastReport'] = abuseIPDBOutput['data']['lastReportedAt']
	output['abuseIPDBDetections']['score'] = abuseIPDBOutput['data']['abuseConfidenceScore']


def compileJSONData():
	allData = {}
	allData['vpnapiOutput'] = vpnapiOutput
	allData['abuseIPDBOutput'] = abuseIPDBOutput
	allData['vtOutput'] = vtOutput
	allData['shodanOutput'] = shodanOutput
	allData['ipinfoOutput'] = ipinfoOutput

	return allData


def buildHTML():

	def writeHTMLToFile(html):

		text_file = open("index.html", "w")
		text_file.write(html)
		text_file.close()


	def boilerplate():
		html = f'<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport"content="width=device-width, initial-scale=1.0">\n<meta http-equiv="X-UA-Compatible"content="ie=edge">\n<title>IP Scout</title>\n<link rel="stylesheet"href="style.css">\n</head>\n<body><div><h1>{output["ip"]}</h1></div>'
		
		return html


	def addLocationDiv(html):

		locationDIV = f'<div><h2>Location</h2>\
		<h3>Country</h3>\
		{output["location"]["country"]}\
		<h3>Region</h3>\
		{output["location"]["region"]}\
		<h3>City</h3>\
		{output["location"]["city"]}\
		<img src="{output["location"]["flagURL"]}"/></div> alt="{output["location"]["country_code"]}_flag"/></div>'

		return html + locationDIV


	def addNetworkDiv(html):
		networkDIV = f'<div><h2>Network<H2>\
		<h3>CIDR</h3>\
		{output["network"]["network"]}\
		<h3>ASN</h3>\
		{output["network"]["autonomous_system_number"]}\
		<h3>ASN Organisation</h3>\
		{output["network"]["autonomous_system_organization"]}\
		<h3>ISP</h3>\
		{output["network"]["isp"]}\
		<h3>Usage Type</h3>\
		{output["network"]["usageType"]}\
		<h3>Domain</h3>\
		{output["network"]["domain"]}\
		<div><h3>IP Traits</h3>\
		<h3>VPN</h3>\
		{output["network"]["isVPN"]}\
		<h3>TOR</h3>\
		{output["network"]["isTOR"]}\
		<h3>Proxy</h3>\
		{output["network"]["isProxy"]}\
		<h3>Relay</h3>\
		{output["network"]["isRelay"]}\
		</div>\
		</div>'

		return html + networkDIV


	def addPortsDiv(html):

		if (output['ports'] == 'No Data Available'):
			portsDIV = f'<div><h2>Open Ports</h2>None found</div>'
			return html + portsDIV

		#compile list of ports
		portList = '<ul>'
		
		for port in output['ports']:
			portList += f'<li>{port}</li>'

		portList += '</ul>'

		portsDIV = f'<h2>Open Ports</h2>{portList}</div>'

		return html + portsDIV


	def addHistoricUrls(html):

		historicUrlsDIV = '<div><h2>Historic URLs</h2>'

		#ensure data exists
		if (len(output['historicURLs']) == 0):
			historicUrlsDIV += 'None found</div>'
			return historicUrlsDIV

		table = '<table><tr><th>URL</th><th>Last Seen</th></tr>'

		for url in output['historicURLs']:
			table += f'<tr><td>{url["hostname"]}</td><td>{url["last_resolved"][:-9]}</td></tr>'

		table += '</table>'

		historicUrlsDIV += (table + '</div>')

		return html + historicUrlsDIV


	def addDetections(html):

		detectionsDIV = '<div><h2>Detections</h2>'

		#add AbuseIPDB data
		if output['abuseIPDBDetections']['totalReports'] > 0:
			abuseIPDBDIV = f'<div><h3>AbuseIPDB</h3>\
			<h4>Hostile</h4>%{output["abuseIPDBDetections"]["score"]}\
			<h4>Reports</h4>{output["abuseIPDBDetections"]["totalReports"]}\
			<h4>Last Report</h4>{output["abuseIPDBDetections"]["lastReport"]}\
			</div>'
		else:
			abuseIPDBDIV = f'<div><h3>AbuseIPDB</h3><h4>No Reports</h4></div>'

		#add Virustotal detections
		if len(output['vtDetections']) > 0:
			virustotalDIV = f'<div><h3>VirusTotal</h3><table>\
			<tr><th>Asset</th><th>Positives</th><th>Scan Date</th></tr>'

			for i in output['vtDetections']:
				virustotalDIV += f'<tr><td>{i["url"]}</td><td>{i["positives"]}/{i["total"]}</td><td>{i["scan_date"]}</td></tr>'

			virustotalDIV += '</table></div>'

		else:
			virustotalDIV = f'<div><h3>VirusTotal</h3><h4>No Reports</h4></div>'

		return html + abuseIPDBDIV + virustotalDIV


	html = boilerplate()
	html = addLocationDiv(html)
	html = addNetworkDiv(html)
	html = addPortsDiv(html)
	html = addHistoricUrls(html)
	html = addDetections(html)
	html += '</body>\n</html>'

	writeHTMLToFile(html)


compileCreds()

vpnapiOutput = getVpnapiOutput(ip)
abuseIPDBOutput = getAbuseIPDBOutput(ip)
vtOutput = getVTOutput(ip)
ipinfoOutput = getIPInfoOutput(ip)
shodanOutput = getShodanOutput(ip)
historicUrls = getHistoricUrls(vtOutput)

allData = compileJSONData()

parseToOutput()

dictToJson(output, outfile)
dictToJson(allData, 'allData.json')

buildHTML()