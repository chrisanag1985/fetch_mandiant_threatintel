import mandiant_threatintel
import json
import configparser
import argparse
from datetime import datetime

# ARGPARSE CONFIGURATOR

description = "Download Mandiant Threat Intelligence Through API"

parser = argparse.ArgumentParser(description=description)

parser.add_argument("-o","--output-file",type=str,help="Name of the Output file (Default: output-startdatetime-enddatetime.json)")
parser.add_argument("-s","--start-datetime",type=str,help="Start Datetime of search | Format dd/mm/YYYY@HH:MM:SS | (Default: Start of current day)")
parser.add_argument("-e","--end-datetime",type=str,help="End Datetime of search | Format dd/mm/YYYY@HH:MM:SS | (Default: Now)")
parser.add_argument("-m","--min-score",type=int,help="Minimum score of confidence (Default: 0)",default=0)
parser.add_argument("-p","--page-size",type=int,help="The number of results to retrieve per page - Not limit the results to retrieve (Default: 1000)",default=1000)
parser.add_argument("--exclude-osint",help="If True, then exclude OSINT from results",action="store_true" )
parser.add_argument("--splunk-convert",help="Add the field `last_seen_index` for splunk consumption",action="store_true")
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


file = open(output_file,"w")
print(f"[+] Start writing in file %s"%output_file)
for obj_indicator in indicators:

    indicator_dict = obj_indicator.__dict__
    indicator = indicator_dict["_api_response"]
    if args.splunk_convert:
        indicator["last_seen_index"] = indicator["last_seen"]
    #print(vars(indicator))

    file.write(json.dumps(indicator)+"\n")


file.close()
print("[+] Writing Ended")
print("[+] Exit")
