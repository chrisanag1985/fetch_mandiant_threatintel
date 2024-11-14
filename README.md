# Fetch Mandiant Threat Intel

Python Script that downloads Mandiant Threat Intel to JSON file for offline consumption.

It can also adds an additional field to be ready for Splunk consumption.

## Dependencies

Install `mandiant_threatintel` dependency from https://github.com/google/mandiant-ti-client

## Configuration

1. Create a `config.ini` is the same folder, based on the `config.ini.template`.
2. Add your API Key/Secret without quotes.

## Usage

For more information type
```bash 
$ python3 main.py  -h
usage: main.py [-h] [-o OUTPUT_FILE] [-s START_DATETIME] [-e END_DATETIME] [-m MIN_SCORE] [-p PAGE_SIZE] [--exclude-osint] [--splunk-convert] [-v]

Download Mandiant Threat Intelligence Through API

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Name of the Output file (Default: output-startdatetime-enddatetime.json)
  -s START_DATETIME, --start-datetime START_DATETIME
                        Start Datetime of search | Format dd/mm/YYYY@HH:MM:SS | (Default: Start of current day)
  -e END_DATETIME, --end-datetime END_DATETIME
                        End Datetime of search | Format dd/mm/YYYY@HH:MM:SS | (Default: Now)
  -m MIN_SCORE, --min-score MIN_SCORE
                        Minimum score of confidence (Default: 0)
  -p PAGE_SIZE, --page-size PAGE_SIZE
                        The number of results to retrieve per page - Not limit the results to retrieve (Default: 1000)
  --exclude-osint       Exclude OSINT from results
  --splunk-convert      Add the field `last_seen_index` for splunk consumption
  -v, --verbose         Print Arguments

```

## Output

JSON file with Mandiant Threat Intel indicators.


## For Splunk Consumption

Add flag `--splunk-convert` in order to add the extra field `last_seen_index` which is used from Mandiant Threat Intel App as timestamp.
