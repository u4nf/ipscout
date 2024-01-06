from shodan import Shodan
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
	
	return client.host(ip)


def getIPInfoOutput(ip):
	#queries ipinfo, view all data with <print(details.all)>

	client = ipinfo.getHandler(APIipinfo)
	details = client.getDetails(ip)
	
	return details


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


def dictToJson(dictIn, outfile):
	# Convert dictionary <dictIn> to JSON and write to file <OUTFILE>

	with open(outfile, "w") as outputFile: 
		jsonObject = json.dumps(dictIn, indent = 4)
		outputFile.write(jsonObject)

		#return jsonObject


def parseToOutput():
	#parses multiple sources into a single output object
	output['isp'] = shodanOutput['isp']
	output['ports'] = shodanOutput['ports']
	output['country'] = shodanOutput['country_name']
	output['ip'] = shodanOutput['ip_str']
	output['asn'] = shodanOutput['asn']
	output['urls'] = urls
	output['flagURL'] = ipinfoOutput.country_flag_url
	output['vtDetections'] = vtOutput['detected_urls']



compileCreds()

vtOutput = getVTOutput(ip)

ipinfoOutput = getIPInfoOutput(ip)

shodanOutput = getShodanOutput(ip)

urls = reverseIPLookup(ip)

parseToOutput()

dictToJson(output, outfile)

#print(output)