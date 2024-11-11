# Fetch Mandiant Threat Intel

Python Script that download Mandiant Threat Intel to JSON file for offline consumption.

It can also adds an additional field to be ready for Splunk consumption

## Dependencies

Install `mandiant_threatintel` dependency from https://github.com/google/mandiant-ti-client

## Configuration

1. Create a `config.ini` is the same folder, based on the `config.ini.template`.
2. Add your API Key/Secret without quotes

## Usage

For more information type
```bash 
python3 main.py -h
```

## Output

JSON file with Mandiant Threat Intel indicators


## For Splunk Consumption

Add flag `--splunk-convert` in order to add the extra field `last_seen_index` which is used from Mandiant Threat Intel App as timestamp.