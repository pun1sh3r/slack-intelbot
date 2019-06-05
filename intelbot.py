import os
import time
import re
from slackclient import SlackClient
import logging
import sys
from pprint import pprint
import requests
from collections import defaultdict
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from ipwhois import IPWhois
from whois import whois
import csv
import json
import websocket

log = logging.getLogger()
log.setLevel(logging.INFO)
formatter = logging.Formatter(fmt='%(asctime)s: %(levelname)s: %(lineno)d : %(message)s')
handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)
log.addHandler(handler)

try:
    import http.client as http_client
except ImportError:
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 1


class intelbot():

    def __init__(self):

        self.slack_client = SlackClient(os.environ.get('SLACK_BOT_TOKEN'))
        self.rtm_read_delay = 1
        self.mention_regex = "^<@(|[WU].+?)>(.*)"
        self.intelbot_id = self.slack_client.api_call("auth.test")['user_id']
        self.vt_api = os.environ.get('VT_API')
        self.abusedb_api = os.environ.get('ABUSEDB_API')
        self.hybrid_api = os.environ.get('HYBRID_API')
        self.output = defaultdict(dict)
        self.channel = os.environ.get("CHANNEL")
        self.file_id = 'none'
    def slack_post_msg(self,msg):

        resp = self.slack_client.api_call(
            "chat.postMessage",
            channel=self.channel,
            text=msg
        )
    def slack_file_upload(self,file,type):
        tmp = ''
        content = ''
        filename = ''
        if type == 'text':
            content = file
            filename = 'output.txt'
        elif type == 'csv':
            with open(file, 'rb') as fh:
                tmp = fh.read()
                filename = file
        res = self.slack_client.api_call(
            "files.upload",
            channels=self.channel,
            content=content,
            filename=filename,
            file = tmp
        )
    def parse_direct_mention(self,event_text):
        matches = re.search(self.mention_regex, event_text)
        return (matches.group(1), matches.group(2).strip()) if matches else (None,None)
    def slack_file_read(self):
        res = self.slack_client.api_call(
            "files.info",
            file=self.file_id
        )

        if res['ok'] == False:
            return False
        else:
            file_url = res['file']['url_private']
            fh = requests.get(file_url, headers={'Authorization': 'Bearer {}'.format(os.environ.get('SLACK_BOT_TOKEN'))})
            file_data = fh.text
            return file_data.split('\n')
    def parse_commands(self, slack_events):
        for event in slack_events:
            if event['type'] == 'message' and not 'subtype' in event:
                user_id, message = self.parse_direct_mention(event['text'])
                if user_id == slack_obj.intelbot_id:
                    log.info("{}-{}".format(message, event['channel']))
                    if 'files' in event:
                        self.file_id= event['files'][0]['id']

                        return message, event['channel'], self.file_id
                    return message, event['channel'],self.file_id
        return None, None, None

    def handle_command(self,command, channel):
        response = "Not sure what you meant. Try < @intelbot > \"1.1.1.1,google[.]com,06060eae9493361eb519d1df65855cd9\" <{}>".format("csv|text ")

        if command.startswith("help"):
            response = '''
        Greetings! I am intelbot at your service. Here is what i can do:

        - look up ip addresses,  domain names and hashes(sha1|md5|sha256) on well known "open source" sites. 

        How to use me (command anatomy) (default output type is text)

        @intelbot ioc1,ioc2 output_type 
        @intelbot 1.1.1.1,2.2.2.2 csv 
  
        bulk searches:
        - upload file to be queried just like a regular upload on slack. each file must contain the same type of indicator e.g hash, ip or domain. once the file is ready to upload on the "add a message about the file section" type the following: @intelbot "file" output_type. the keyword "file" is needed to be able to parse the file properly.
        
        output types: csv|text 

                    '''
            self.slack_post_msg(response)
            return

        cmd = command.split(' ')
        cmd_length = len(cmd)
        if cmd_length > 2:
            self.slack_post_msg(response)
            return
        try:
            output_format = cmd[1]
        except IndexError:
            output_format = 'text'

        if cmd[0] == 'file':
            ioc_list = self.slack_file_read()
        if self.slack_file_read() == False:
            ioc_list = cmd[0].split(',')
        self.slack_post_msg("Querying your indicators, just a sec.....")
        for ioc in ioc_list:
            ioc = ioc.rstrip()
            tags = set()
            if self.is_ip(ioc) == True:
                self.query_vt([ioc],'ip')
                self.query_otx([ioc], 'ip', 'none')
                self.query_abusedb([ioc])
            elif 'True' in self.is_hash(ioc):
                h_check = self.is_hash(ioc).split('-')[1]
                self.query_vt([ioc], 'hash')
                self.query_otx([ioc], 'hash', h_check)
                #self.query_h_analysis([ioc])
                self.query_urlhaus([ioc],h_check)

            elif self.is_domain(ioc) == True:
                ioc = re.sub(r'(>|\[|\]|\s)','',ioc)
                self.query_vt([ioc], 'domain')
                self.query_otx([ioc], 'domain', 'None')
                self.query_whois([ioc])
                self.query_urlhaus([ioc], 'domain')
            elif ioc == '':
                continue
            else:
                self.slack_post_msg(response)
                return

        if output_format == 'csv':
            self.craft_csv()

        if output_format == 'text':
            output = json.dumps(self.output, indent=4)
            self.slack_file_upload(output,output_format)
        return

    def craft_csv(self):
        with open('tmp.csv', 'w') as csvfile:
            uniq_fields = set()
            fieldnames = [uniq_fields.add(k) for key in self.output.keys() for k in self.output[key].keys()]
            writer = csv.DictWriter(csvfile, fieldnames=sorted(uniq_fields))
            writer.writeheader()
            for key, value in self.output.items():
                writer.writerow(value)
        self.slack_file_upload('tmp.csv','csv')
    def query_whois(self,domains):
        for dom in domains:
            try:
                who_is = whois(dom)
                date = who_is.creation_date.date()
                print(type(date))
                self.output[dom].update({'registrar': who_is.registrar })
                self.output[dom].update({'emails' : who_is.emails })
                self.output[dom].update({'creation_date' : str(date)})
            except Exception as ex:
                log.info("[*] exception caught inside query_whois {}".format(ex))
    def query_ip_whois(self,ip):
        # this function will be deleted soon.
        #for ip in ips:
        ip_whois  = IPWhois(ip)
        ip_whois = ip_whois.lookup_whois()
        self.output[ip].update({'asn': ip_whois['asn_description']})
    def is_hash(self,hash):
        sha1_regex = r'(?=(\b[A-Fa-f0-9]{40}\b))'
        md5_regex = r'(?=(\b[A-Fa-f0-9]{32}\b))'
        sha256_regex = r'(?=(\b[A-Fa-f0-9]{64}\b))'
        if re.search(sha1_regex, hash):
            return 'True-sha1'
        elif re.search(md5_regex, hash):
            return 'True-md5'
        elif re.search(sha256_regex, hash):
            return 'True-sha256'
        else:
            return 'False'
    def is_domain(self, domain):
        domain = domain.rstrip()
        if domain:
            domain = domain.replace('[.]','.')
            dom_regex = r'\A([a-z0-9]+(-[a-z0-9]+)*\[?\.\]?)+[a-z]{2,}\Z'
            if re.search(dom_regex, domain) == None:
                return False
            else:
                return True
    def is_ip(self, ip):
        ip_regex = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.search(ip_regex, ip) == None:
            return False
        else:
            return True
    def query_h_analysis(self, hashes):
        for hash in hashes:
            headers = {'api-key': self.hybrid_api, 'user-agent' : 'Falcon Sandbox'}
            data = {'hash' : hash}
            try:
                if hash.rstrip():
                    req = requests.post('https://www.hybrid-analysis.com/api/v2/search/hash'.format(hash),data=data,headers=headers)
                    res = req.json()[0]
                    self.output[hash].update({'Hybrid_analysis_threat_score' : '{} out of 100'.format(res['threat_score'])})
                    self.output[hash].update({'Hybrid_analysis_verdict': res['verdict']})
            except Exception as ex:
                self.output[hash].update({'hybrid-analysis': 'not present'})
                log.info("exception {}".format(ex))
                return
    def query_geo(self,ips):
        #::delete this function since otx already provides this.
        for ip in ips:
            #::perform exception handling just in case site goes down.
            #self.output[ip]['geo'] = {}
            req = requests.get("http://api.hackertarget.com/geoip/?q={}".format(ip))
            resp =  dict(i.split(':') for i in req.text.split('\n'))
            self.output[ip]['geo'].update(resp)
    def query_otx(self,iocs, ioc_type, hash_type):
        otx  = OTXv2(os.environ.get('OTX_API'))
        for ioc in iocs:
            try:
                if ioc.rstrip():
                    tags = set()
                    indicator_type = ''
                    if ioc_type == 'hash':
                        ##this might not work wince it doesnt provide useful data
                        if hash_type == 'sha1':
                            indicator_type = IndicatorTypes.FILE_HASH_SHA1
                        elif hash_type == 'sha256':
                            indicator_type = IndicatorTypes.FILE_HASH_SHA256
                        elif hash_type == 'md5':
                            indicator_type = IndicatorTypes.FILE_HASH_MD5


                        data = otx.get_indicator_details_by_section(indicator_type,ioc,'general')
                        tag_data = data['pulse_info']['pulses']
                        tag_data = [tags.add(tag['name']) for tag in tag_data]

                        if tags:
                            self.output[ioc].update({'otx_tags': ",".join(tags)})

                    if ioc_type == 'ip':

                        indicator_type = IndicatorTypes.IPv4
                        otx_data = otx.get_indicator_details_by_section(indicator_type, ioc, 'general')
                        reputation = otx.get_indicator_details_by_section(indicator_type, ioc, 'reputation')
                        tag_data = otx_data['pulse_info']['pulses']
                        tag_data = [tags.add(t) for tag in tag_data for t in tag['tags']]
                        reputation = reputation['reputation']
                        self.output[ioc].update({'otx-asn' : otx_data['asn']})
                        if bool(reputation) == False:
                            #self.query_ip_whois(ioc)
                            self.output[ioc].update({'data': 'none'})
                            self.output[ioc].update({'otx_tags': ",".join(tags)})
                            continue
                        self.output[ioc].update({'otx_tags': ",".join(tags)})
                        self.output[ioc].update({'otx_threat_score': '{} out of (7) '.format(reputation['threat_score'])})
                        self.output[ioc].update({'otx_first_seen': reputation['first_seen']})
                        self.output[ioc].update({'otx_last_seen': reputation['last_seen']})
                        self.output[ioc].update({'otx_sites_blacklisted': len(
                            reputation['matched_bl']) if 'matched_bl' in reputation else 'none'})

                    if ioc_type == 'domain':
                        '''
                        for domain the following sections are available
                        'sections': ['general',
                                      'geo',
                                      'url_list',
                                      'passive_dns',
                                      'malware',
                                      'whois',
                                      'http_scans'],
                                      
                        geo section returns the following data 
                        {'area_code': 0,
                             'asn': 'AS16276 OVH SAS',
                             'charset': 0,
                             'city': 'Paris',
                             'city_data': True,
                             'continent_code': 'EU',
                             'country_code': 'FR',
                             'country_code3': 'FRA',
                             'country_name': 'France',
                             'dma_code': 0,
                             'flag_title': 'France',
                             'flag_url': '/static/img/flags/fr.png',
                             'latitude': 48.86280059814453,
                             'longitude': 2.329200029373169,
                             'postal_code': '75001',
                             'region': 'A8'}
                        '''
                        indicator_type = IndicatorTypes.DOMAIN
                        dom_data = otx.get_indicator_details_by_section(indicator_type, ioc, 'general')
                        dom_data = dom_data['pulse_info']['pulses']
                        dom_data = [tags.add(t) for tag in dom_data for t in tag['tags']]
                        self.output[ioc].update({'otx_tags' : ",".join(tags)})
                    if ioc_type == 'domain' or ioc_type == 'ip':
                        geo = otx.get_indicator_details_by_section(indicator_type, ioc, 'geo')
                        self.output[ioc].update({'otx_asn': '{}/{}'.format(geo['asn'], geo['country_name'])})
            except Exception as ex:
                self.output[ioc].update({'otx-found': 'no'})
                log.info("[*] Otx exception {}".format(ex))
                return


            #check for ioc type for validation.
            #test = otx.get_indicator_details_full(indicator_type,ioc)
            #pprint(test)
    def query_vt(self,iocs,ioc_type):
        results = ''
        for ioc in iocs:
            params = ''
            url_param = ''
            if ioc.rstrip():
                self.output[ioc].update({'_observable': ioc })
                if ioc_type == 'ip':
                    params = {'ip': ioc, 'apikey' : self.vt_api }
                    url_param = 'ip-address'
                if ioc_type == 'domain':
                    params = {'domain': ioc, 'apikey': self.vt_api}
                    url_param = 'domain'

                if ioc_type == 'hash':
                    params = {'resource' : ioc , 'apikey' : self.vt_api }
                    url_param = 'file'
                headers = {
                    'Accept-Encoding' : 'gzip, deflate',
                    "User-Agent" : "intelbot "
                }
                req = requests.get('https://www.virustotal.com/vtapi/v2/{}/report'.format(url_param), params=params,headers=headers)
                if req.status_code != 200:
                    continue
                resp = req.json()
                link = 'https://www.virustotal.com/en/{}/{}/information/'.format(url_param, ioc)
                for key, value in resp.items():
                    if key == 'detected_downloaded_samples':
                        self.output[ioc].update(
                            {'Virus_total_detected_downloaded_samples': len(resp['detected_downloaded_samples'])})
                    elif key == 'detected_urls':
                        self.output[ioc].update({
                            'Virus_total_detected_urls': len(resp['detected_urls'])})
                    elif key == 'positives':
                        self.output[ioc].update({
                            'Virus_total_Detections (AV):': resp['positives']})
                        link = 'https://www.virustotal.com/en/{}/{}/analysis/'.format(url_param, resp['sha256'])
                    elif key == 'detected_communicating_samples':
                        self.output[ioc].update(
                            {'Virus_total_detected_communicating_samples': len(resp['detected_communicating_samples'])})
                    try:
                        self.output[ioc].update({'Virus_total_Mcafee_detected': resp['scans']['McAfee']['detected']})
                    except Exception as ex:
                        self.output[ioc].update({'Virus_total_Mcafee_detected': 'False'})
                    self.output[ioc].update(
                        {'link': link })
    def query_abusedb(self,ips):
        for ip in ips:
            if ip.rstrip():
                params = {'ipAddress': ip ,'verbose': 'yes', 'maxAgeInDays' : '90'}
                headers = {'Accept' : 'application/json', 'key' : self.abusedb_api}
                req = requests.get('https://api.abuseipdb.com/api/v2/check',params=params,headers=headers)
                if req.status_code == 200:
                    resp = req.json()
                    self.output[ip].update({'Abuse_db_confidence_score': resp['data']['abuseConfidenceScore']})
                    self.output[ip].update({'Abuse_db_total_reports': resp['data']['totalReports']})
                else:
                    self.output[ip].update({'AbuseDB' : 'not-available'})
    def query_urlhaus(self,iocs,ioc_type):
        for ioc in iocs:
            data = ''
            api = ''
            try:
                tags =set()
                if ioc_type == 'domain':
                    data = {'host' : iocs}
                    api = 'https://urlhaus-api.abuse.ch/v1/host/'
                elif ioc_type == 'sha256' or ioc_type == 'md5':
                    data = {'{}_hash'.format(ioc_type) : iocs}
                    api = 'https://urlhaus-api.abuse.ch/v1/payload/'
                else:
                    return
                req = requests.post(api, data=data)
                resp = req.json()
                if resp['query_status'] == 'no_results':
                    self.output[ioc].update({'urlhaus': 'no_results'})
                    continue
                if len(resp['urls']) > 1:
                    #if  e['tags'] == None
                    [tags.add(t) for e in resp['urls'] if 'tags' in e if not e['tags'] == None for t in e['tags']]
                    self.output[ioc].update({'urlhaus_tags': ','.join(tags)})
                self.output[ioc].update({'urlhaus_signature': resp['signature'] if 'signature' in resp else 'none' } )
                self.output[ioc].update({'urlhaus_firstseen': resp['firstseen'] if 'firstseen' in resp else 'none'})
                self.output[ioc].update({'urlhaus_lastseen' : resp['lastseen'] if 'lastseen' in resp else 'none' })
                self.output[ioc].update({'urlhaus_malicious_url' : resp['url_count']})

            except Exception as ex:
                log.info("json exception on {} {}".format(ex, iocs))

if __name__ == "__main__":
    slack_obj = intelbot()
    s_client = slack_obj.slack_client

    if s_client.rtm_connect(with_team_state=False,auto_reconnect=True):
        log.info("intelbot initiated and running...")
        intelbot_id = s_client.api_call("auth.test")['user_id']
        log.info(intelbot_id)
        while True:
            try:
                command,channel,file_id  = slack_obj.parse_commands(s_client.rtm_read())
                if command:
                    slack_obj.handle_command(command,channel)

                time.sleep(slack_obj.rtm_read_delay)
                slack_obj.output.clear()
            except websocket.WebSocketConnectionClosedException as ex:
                log.info("[*] Caught websocket disconnect {}, reconnecting...".format(ex))
                time.sleep(1)
                s_client.rtm_connect()
            except Exception as ex:
                log.info("[*] Exception caught {}".format(ex))
                s_client.rtm_connect()
    else:
        s_client.rtm_connect()
        log.info("{}".format("Connection failed. "))