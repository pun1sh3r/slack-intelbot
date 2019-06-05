# slack-intelbot

This is a piece of hackish code that aims to help analysts with atomic indicator research. The sources the bot uses are:
- Virustotal
- abuseip
- urlhaus
- hybrid analysis
- Alienvault OTX
   
### Requirements
a slackbot app is needed to implement this code. The guide on how to create a slackbot is [here](https://get.slack.help/hc/en-us/articles/115005265703-Create-a-bot-for-your-workspace) 

### Installation instructions
start by installing the python depencies needed to run the script. It is recommented to use virtualenv. Instructions on how to install virtualenv are [here](https://gist.github.com/frfahim/73c0fad6350332cef7a653bcd762f08d). after virtualenv is install run the following commands:

```angular2html
pip install -r requirements.txt
```

Populate the config file `config.ini` with the corresponding api keys.
```angular2html
export SLACK_BOT_TOKEN='apikey'
export VT_API='apikey'
export OTX_API='apikey'
export ABUSEDB_API='apikey'
export HYBRYD_API='apikey'
export CHANNEL='intelbot-dev'
```

Load the config file on your virtual environment.

```angular2html
source config.ini
```

## Intelbot Usage.

See intelbot help menu below:

```angular2html
@intelbot help

Greetings! I am intelbot at your service. Here is what i can do:

       - look up ip addresses,  domain names and hashes(sha1|md5|sha256) on well known "open source" sites.

       How to use me (command anatomy) (default output type is text and indicators are comma separated)

       @intelbot ioc1,ioc2 output_type
       @intelbot 1.1.1.1,2.2.2.2 csv
 
       bulk searches:
       - upload file to be queried just like a regular upload on slack.  once the file is ready to upload on the "add a message about the file section" type the following: @intelbot "file" output_type. the keyword "file" is needed to be able to parse the file properly.
       
       output types: csv|text

```
intelbot searches the following types of atomic indicators: `domains`, `ip addresses` and `hashes(md5,sha1,sha256)`.

- to search any type on indicator and output results in txt format (commands are ran on the slack message window). :
```angular2html
@intelbot vektorex[.]com,12c8aec5766ac3e6f26f2505e2f4a8f2,1.1.1.1


command result:
{
    "vektorex.com": {
        "_observable": "vektorex.com",
        "Virus_total_Mcafee_detected": "False",
        "link": "https://www.virustotal.com/en/domain/vektorex.com/information/",
        "Virus_total_detected_downloaded_samples": 100,
        "Virus_total_detected_communicating_samples": 100,
        "Virus_total_detected_urls": 100,
        "otx_tags": "Malspam,site",
        "otx_asn": "AS34619 Cizgi Telekomunikasyon Anonim Sirketi/Turkey",
        "registrar": "NICS Telekomunikasyon A.S.",
        "emails": "abuse@nicproxy.com",
        "creation_date": "2018-09-22",
        "urlhaus_tags": "Formbook,NanoCore,doc,remcos,AZORult,exe,emotet,HawkEye,payload,RemcosRAT,quasar,stage2,lokibot,rat,Loki,QuasarRAT",
        "urlhaus_signature": "none",
        "urlhaus_firstseen": "2019-01-15 07:09:01 UTC",
        "urlhaus_lastseen": "none",
        "urlhaus_malicious_url": "124"
    },
    "12c8aec5766ac3e6f26f2505e2f4a8f2": {
        "_observable": "12c8aec5766ac3e6f26f2505e2f4a8f2",
        "Virus_total_Mcafee_detected": true,
        "link": "https://www.virustotal.com/en/file/01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b00/analysis/",
        "Virus_total_Detections (AV):": 34,
        "urlhaus_tags": "",
        "urlhaus_signature": "Heodo",
        "urlhaus_firstseen": "2019-01-19 01:27:04",
        "urlhaus_lastseen": "2019-01-19 02:11:26",
        "urlhaus_malicious_url": "138"
    },
    "1.1.1.1": {
        "_observable": "1.1.1.1",
        "Virus_total_Mcafee_detected": "False",
        "link": "https://www.virustotal.com/en/ip-address/1.1.1.1/information/",
        "Virus_total_detected_downloaded_samples": 1,
        "Virus_total_detected_communicating_samples": 100,
        "Virus_total_detected_urls": 100,
        "otx-asn": "AS13335 Cloudflare, Inc.",
        "data": "none",
        "otx_tags": "",
        "Abuse_db_confidence_score": 0,
        "Abuse_db_total_reports": 30
    }
}


```

- to search any type on indicator and output results in `csv` format. :
```angular2html
@intelbot 12c8aec5766ac3e6f26f2505e2f4a8f2


command result:

Virus_total_Detections (AV):,Virus_total_Mcafee_detected,_observable,link,urlhaus_firstseen,urlhaus_lastseen,urlhaus_malicious_url,urlhaus_signature,urlhaus_tags
34,True,12c8aec5766ac3e6f26f2505e2f4a8f2,https://www.virustotal.com/en/file/01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b00/analysis/,2019-01-19 01:27:04,2019-01-19 02:11:26,138,Heodo,

```

- bulks searches are done by performing a regular file upload. When uploading the file there is a textbox that says `add a message about the file`. on that textbot the following command below should be typed. The keyword `file` is essential so the bot knows is a file.By default the output format is `csv` but it also supports `txt` format:

```angular2html
@intelbot file 
```

