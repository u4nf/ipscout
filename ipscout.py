from shodan import Shodan
from datetime import datetime
from operator import itemgetter
import ipinfo
import json, pprint, requests, argparse, csv, logging, sys, base64

#parse arguments
parser = argparse.ArgumentParser(description='A commandline tool to retrieve metadata about an IP from multiple sources.')
parser.add_argument('-i', type=str, default='8.8.8.8', help='The IP address to scout')
parser.add_argument('-o', type=str, help='JSON output file name')
args=parser.parse_args()

#set variables
ip = args.i
outfile = args.o
output = {}
logfile = 'ipScout.log'

#configure logger
logging.basicConfig(handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(logfile, mode="a"),],level=logging.DEBUG,format='%(asctime)s[%(levelname)s]: %(message)s', datefmt='%d-%m-%Y %H:%M:%S',)


def showLogo():
	print(r"""
	 ___  ________  ________  ________  ________  ___  ___  _________   
	|\  \|\   __  \|\   ____\|\   ____\|\   __  \|\  \|\  \|\___   ___\ 
	\ \  \ \  \|\  \ \  \___|\ \  \___|\ \  \|\  \ \  \\\  \|___ \  \_| 
	 \ \  \ \   ____\ \_____  \ \  \    \ \  \\\  \ \  \\\  \   \ \  \  
	  \ \  \ \  \___|\|____|\  \ \  \____\ \  \\\  \ \  \\\  \   \ \  \ 
	   \ \__\ \__\     ____\_\  \ \_______\ \_______\ \_______\   \ \__\
	    \|__|\|__|    |\_________\|_______|\|_______|\|_______|    \|__|
	                  \|_________|                                      
	                                                                    
	                                                                    """)


def compileCreds():

	def compileXforceCreds(XforceCreds):
		#create global dictionary
		global APIXFORCE
		APIXFORCE = {}

		APIXFORCE['key'] = XforceCreds[1]
		APIXFORCE['password'] = XforceCreds[2]


	#Take creds from csv, populate global variables
	#Xforce creds must be the first row due to the key / password format
	logging.debug('Commence cred compile')
	creds = []

	credsPath = './creds.csv'
	with open(credsPath, 'r') as infile:
		reader = csv.reader(infile)

		for row in reader:
			creds.append(row)

		#create XForce variabe and remove from creds list
		compileXforceCreds(creds[0])
		creds = creds[1:]

	#iterate over list, set index 0 as the variable name, index 1 as the value
	for i in creds:
		globals()[i[0]] = i[1]
        

def getXForceOutput(ip):

	def createB64(api_key, api_password):
		#encode api creds for use with API

		string_format = f'{api_key}:{api_password}'.encode()
		base64_format = f'Basic {base64.b64encode(string_format).decode()}'

		return base64_format


	url = f'https://api.xforce.ibmcloud.com/api/ipr/{ip}'
	headers = {'Authorization': createB64(APIXFORCE['key'], APIXFORCE['password'])}

	response = requests.get(url, headers=headers)

	return json.loads(response.text)


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

	historicUrls = []
	
	if (len(vtOutput['resolutions']) > 0):

		for i in vtOutput['resolutions']:
			historicUrls.append(i)

	#order by date desc
	historicUrls = sorted(historicUrls, key=itemgetter("last_resolved"), reverse=True)

	return historicUrls


def getIPApiOutput(ip):
	url = f'http://api.ipapi.com/api/{ip}?access_key={APIIPAIP}'
	response = requests.request(method='GET', url=url)

	return json.loads(response.text)


def parseToOutput():

	def getXforceHistory(num):
		#returns dict containing the <NUM> most recent detections

		def get_created_date(entry):
			return datetime.strptime(entry['created'], "%Y-%m-%dT%H:%M:%S.%fZ")


		def get_recent_entries(historicData):

			def sort_by_created(entry):
				return get_created_date(entry)


			# Sort the history_data based on the "created" field in descending order
			sorted_history = sorted(historicData, key=sort_by_created, reverse=True)

			# Return the three most recent entries
			return sorted_history[:num]


		return get_recent_entries(xforceOutput['history'])


	#parses multiple sources into a single output object
	output['location'] = vpnapiOutput['location']
	output['location']['flagURL'] = ipinfoOutput['country_flag_url']
	output['location']['city'] = ipinfoOutput['city']
	output['location']['region'] = ipinfoOutput['region']
	output['network'] = vpnapiOutput['network']
	output['network']['isp'] = abuseIPDBOutput['data']['isp']
	output['network']['usageType'] = abuseIPDBOutput['data']['usageType']
	output['network']['domain'] = abuseIPDBOutput['data']['domain']
	output['VPNData'] = {}
	output['VPNData']['VPN'] = vpnapiOutput['security']['vpn']
	output['VPNData']['TOR'] = vpnapiOutput['security']['tor']
	output['VPNData']['Proxy'] = vpnapiOutput['security']['proxy']
	output['VPNData']['Relay'] = vpnapiOutput['security']['relay']
	output['ports'] = shodanOutput['ports']
	output['ip'] = vpnapiOutput['ip']
	output['flag'] = ipapiOutput['location']['country_flag']
	output['historicURLs'] = historicUrls
	output['vtDetections'] = vtOutput['detected_urls']
	output['abuseIPDBDetections'] = {}
	output['abuseIPDBDetections']['totalReports'] = abuseIPDBOutput['data']['totalReports']
	output['abuseIPDBDetections']['lastReport'] = abuseIPDBOutput['data']['lastReportedAt']
	output['abuseIPDBDetections']['score'] = abuseIPDBOutput['data']['abuseConfidenceScore']
	output['xforceData'] = {}
	output['xforceData']['score'] = xforceOutput['score']
	output['xforceData']['categories'] = xforceOutput['cats']
	output['xforceData']['history'] = getXforceHistory(10)


def compileJSONData():
	allData = {}
	allData['xforceOutput'] = xforceOutput
	allData['vpnapiOutput'] = vpnapiOutput
	allData['abuseIPDBOutput'] = abuseIPDBOutput
	allData['vtOutput'] = vtOutput
	allData['shodanOutput'] = shodanOutput
	allData['ipinfoOutput'] = ipinfoOutput
	allData['ipapiOutput'] = ipapiOutput

	return allData


def buildHTML():

	def writeHTMLToFile(html):

		text_file = open("index.html", "w")
		text_file.write(html)
		text_file.close()


	def boilerplate():
		html = f'<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport"content="width=device-width, initial-scale=1.0">\n<meta http-equiv="X-UA-Compatible"content="ie=edge">\n<title>IP Scout</title>\n<link rel="stylesheet"href="styles.css">\n</head>\n<body>'
		
		return html


	def addLocationDiv(html):

		locationDIV = f'<div><h2>Location</h2>\
		<h3>Country</h3>\
		{output["location"]["country"]}\
		<h3>Region</h3>\
		{output["location"]["region"]}\
		<h3>City</h3>\
		{output["location"]["city"]}\
		<img src="{output["flag"]}" alt="{output["location"]["country_code"]}_flag"/></div>'

		return locationDIV


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
		</div>'

		return networkDIV


	def addPortsDiv(html):

		if (output['ports'] == 'No Data Available'):
			portsDIV = f'<div><h2>Open Ports</h2>None found</div>'
			return portsDIV

		#compile list of ports
		portList = '<ul>'
		
		for port in output['ports']:
			portList += f'<li>{port}</li>'

		portList += '</ul>'

		portsDIV = f'<h2>Open Ports</h2>{portList}</div>'

		return portsDIV


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

		return historicUrlsDIV


	def addDetections(html):

		detectionsDIV = '<div><h2>Detections</h2>'

		#add AbuseIPDB data
		if output['abuseIPDBDetections']['totalReports'] > 0:
			abuseIPDBDIV = f'<div><h3>AbuseIPDB</h3>\
			<h4>Hostile</h4>{output["abuseIPDBDetections"]["score"]}%\
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


	def addXforecHistory(html):
		xforceHistoryDIV = '<div><h2>XForce Detections</h2>'

		#create detections table, set quantity in <parseToOutput()>
		if len(output['xforceData']['history']) > 0:
			#create table
			table = '<table><tr><th>Timestamp</th><th>Reporting Country</th><th>Reason</th><th>Confidence</th></tr>'

			for i in output['xforceData']['history']:
				table += f'<tr><td>{i["created"][:10]}</td><td>{i["geo"]["country"]}</td><td>{i["reason"]}</td><td>{i["score"] * 10}</td></tr>'

			table += '</table>'

		xforceHistoryDIV += table + '</div>'

		return xforceHistoryDIV


	def addHeaderDiv(html):

		def detectionsDIV():
			#build table div from detection engines

			detectionsDIV = f'<div><table><tr><th>Engine</th><th>Score</th></tr>\
			<tr><td>AbuseIPDB</td><td>{output["abuseIPDBDetections"]["score"]}%</td></tr>'

			if output["abuseIPDBDetections"]["score"] > 0:
				detectionsDIV += f'<tr><td columns="2">{output["abuseIPDBDetections"]["lastReport"][:-15]}</td></tr>'

			detectionsDIV += f'<tr><td>IBM XForce</td><td>{int(output["xforceData"]["score"] * 10)}%</td></tr>'

			#add XForce categories
			for key, value in output['xforceData']['categories'].items():
				detectionsDIV += f'<tr><td>XForce {key}</td><td>{value}%</td></tr>'

			#add VT detections
			vtdetections = ''
			
			for i in output['vtDetections']:
				vtdetections += f'<tr><td>{i["url"]}</td><td>{i["positives"]} / {i["total"]}</td></tr>\
				<tr><td colspan="2">{i["scan_date"][:-9]}</td></tr>'

			detectionsDIV += vtdetections

			detectionsDIV += '</table></div>'

			return detectionsDIV


		def vpnDIV():
			#build table div from vpnapi data

			vpnDIV = f'<div><table>'

			for key, value in output["VPNData"].items():

				if value:
					vpnDIV += f'<tr class="highlight"><td>{key}</td><td>{value}</td></tr>'
				else:
					vpnDIV += f'<tr class="dull"><td>{key}</td><td>{value}</td></tr>'

			return vpnDIV + '</table></div>'


		headerDIV = f'<div><h1>{output["ip"]}</h1>'
		headerDIV += detectionsDIV() + vpnDIV() + '</div>'
		
		return headerDIV 
		

	html = boilerplate()
	html += addHeaderDiv(html)
	html += addLocationDiv(html)
	html += addNetworkDiv(html)
	html += addPortsDiv(html)
	html += addHistoricUrls(html)
	html += addXforecHistory(html)
	#html += addDetections(html)
	html += '</body>\n</html>'

	writeHTMLToFile(html)






showLogo()

compileCreds()
ipapiOutput = getIPApiOutput(ip)
xforceOutput = getXForceOutput(ip)
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


