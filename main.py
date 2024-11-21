import mandiant_threatintel
import json
import configparser
import argparse
import sys
from datetime import datetime

# ARGPARSE CONFIGURATOR

description = "Download Mandiant Threat Intelligence Through API"

parser = argparse.ArgumentParser(description=description)

parser.add_argument("-o","--output-file",type=str,help="Name of the Output file (Default: output-startdatetime-enddatetime.json)")
parser.add_argument("-s","--start-datetime",type=str,help="Start Datetime of search | Format dd/mm/YYYY@HH:MM:SS | (Default: Start of current day)")
parser.add_argument("-e","--end-datetime",type=str,help="End Datetime of search | Format dd/mm/YYYY@HH:MM:SS | (Default: Now)")
parser.add_argument("-m","--min-score",type=int,help="Minimum score of confidence (Default: 0)",default=0)
parser.add_argument("-p","--page-size",type=int,help="The number of results to retrieve per page - Not limit the results to retrieve (Default: 1000)",default=1000)
parser.add_argument("--exclude-osint",help="Exclude OSINT from results",action="store_true" )
parser.add_argument("--splunk-convert",help="Make transformations for splunk consumption",action="store_true")
parser.add_argument("-v","--verbose",help="Print Arguments",action="store_true")
args= parser.parse_args()

if args.verbose:
    print(args)

if (args.start_datetime != None):
    start_datetime= datetime.strptime(args.start_datetime,"%d/%m/%Y@%H:%M:%S")
else:
    start_datetime = datetime.combine(datetime.today(),datetime.min.time())

if (args.end_datetime != None):
    end_datetime= datetime.strptime(args.end_datetime,"%d/%m/%Y@%H:%M:%S")
else:
    end_datetime= datetime.now()

if (args.output_file != None):
    output_file = args.output_file
else: 
    filename_template = "output-"+start_datetime.strftime("%d%m%Y_%H%M%S")+"-"+end_datetime.strftime("%d%m%Y_%H%M%S")+".json"
    output_file = filename_template


# LOAD CONFIG
config = configparser.ConfigParser()
config.read('config.ini')
api_key = config["MANDIANT_CONFIG"]["api_key"]
secret_key = config["MANDIANT_CONFIG"]["secret_key"]

mati_client = mandiant_threatintel.ThreatIntelClient(api_key=api_key,secret_key=secret_key)


"""
https://github.com/google/mandiant-ti-client/blob/main/mandiant_threatintel/threat_intel_client.py

Args:
      minimum_mscore: A minimum 'mscore', or 'confidence'.
      exclude_osint: If True, then exclude Open Source Intelligence from results
      start_epoch: A datetime object representing the start of the time range
      end_epoch: An optional datetime object representing the end of the time
        range to retrieve.  Defaults to "now"
      page_size: The number of results to retrieve from MATI per page.  Does not
        limit the total number of results to retrieve
"""

print(f"[+] Download Indicators from %s to %s"%(start_datetime,end_datetime))

indicators = mati_client.Indicators.get_list(start_epoch=start_datetime,end_epoch=end_datetime,minimum_mscore=args.min_score,exclude_osint=args.exclude_osint,page_size=args.page_size)


# from Splunk Advantage App bin/input_module_mandiant_advantage_indicators.py
def build_category_list(indicator) -> list:
  categories = []
  for source in indicator.sources:
    for category in source.get('category'):
      if category not in categories:
        categories.append(category)
  return categories


def build_attribution_list(indicator, attribution_type: str) -> list:
  attribution_list = []
  if "attributed_associations" not in indicator._api_response:
    return attribution_list

  for assoc in indicator._api_response.get('attributed_associations'):
    if assoc.get('type') == attribution_type:
      attribution_list.append(f"{assoc.get('id')}||{assoc.get('name')}")

  return attribution_list


def build_campaign_list(indicator) -> list:
  campaigns = []
  if "campaigns" not in indicator._api_response:
    return campaigns

  for campaign in indicator.campaigns:
    campaigns.append(f"{campaign.id}||{campaign.name}")

  return campaigns


def build_report_list(indicator) -> list:
  reports = []
  
  for report in indicator.reports:
    reports.append(report.report_id)
  
  return reports





file = open(output_file,"w")
print(f"[+] Start writing in file %s"%output_file)
count = 0
for indicator in indicators:


    event_data: dict = indicator._api_response
    if args.splunk_convert:
        event_data['last_seen_index'] = indicator._api_response.get('last_seen')

        if indicator.type == "md5":
            indicator._api_response['sha1'] = indicator.sha1
            indicator._api_response['sha256'] = indicator.sha256

        # Add category key
        event_data['category'] = build_category_list(indicator)

        # Add threat_actor key
        event_data['threat_actor'] = build_attribution_list(indicator, "threat-actor")

        # Add malware key
        event_data['malware'] = build_attribution_list(indicator, "malware")

        # Add campaign_list key
        event_data['campaigns_list'] = build_campaign_list(indicator)

        # Add reports_list key
        event_data['reports_list'] = build_report_list(indicator)


    file.write(json.dumps(event_data)+"\n")
    count = count + 1
    sys.stdout.write("\r Indicators processed: "+str(count))
    sys.stdout.flush()

print("\n")
file.close()
print("[+] Writing Ended")
print("[+] Exit")
