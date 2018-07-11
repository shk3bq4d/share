#!/usr/bin/env python
# -*- coding: utf-8 -*-
# /* ex: set filetype=python ts=4 sw=4 expandtab: */

import os
import sys
import re
import argparse
import logging
from pygrok import Grok

from pprint import pprint, pformat

logger = logging.getLogger(__name__)
blablaken_patterns = {
    'BASE10NUM': r'(?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))',
    'BASE16FLOAT': r'\b(?<![0-9A-Fa-f.])(?:[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+)))\b',
    'BASE16NUM': r'(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))',
    'CISCOMAC': r'(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})',
    'COMBINEDAPACHELOG': r'%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}',
    'COMMONAPACHELOG': r'%{IPORHOST:clientip} %{HTTPDUSER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)',
    'COMMONMAC': r'(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})',
    'DATA': r'.*?',
    'DATE': r'%{DATE_US}|%{DATE_EU}',
    'DATE_EU': r'%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}',
    'DATE_US': r'%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}',
    'DATESTAMP': r'%{DATE}[- ]%{TIME}',
    'DATESTAMP_EVENTLOG': r'%{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}',
    'DATESTAMP_OTHER': r'%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}',
    'DATESTAMP_RFC2822': r'%{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}',
    'DATESTAMP_RFC822': r'%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}',
    'DAY': r'(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)',
    'EMAILADDRESS': r'%{EMAILLOCALPART}@%{HOSTNAME}',
    'EMAILLOCALPART': r'[a-zA-Z][a-zA-Z0-9_.+-=:]+',
    'GREEDYDATA': r'.*',
    'HOSTNAME': r'\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)',
    'HOSTPORT': r'%{IPORHOST}:%{POSINT}',
    'HOUR': r'(?:2[0123]|[01]?[0-9])',
    'HTTPD_ERRORLOG': r'%{HTTPD20_ERRORLOG}|%{HTTPD24_ERRORLOG}',
    'HTTPD20_ERRORLOG': r'\[%{HTTPDERROR_DATE:timestamp}\] \[%{LOGLEVEL:loglevel}\] (?:\[client %{IPORHOST:clientip}\] ){0,1}%{GREEDYDATA:errormsg}',
    'HTTPD24_ERRORLOG': r'\[%{HTTPDERROR_DATE:timestamp}\] \[%{WORD:module}:%{LOGLEVEL:loglevel}\] \[pid %{POSINT:pid}:tid %{NUMBER:tid}\]( \(%{POSINT:proxy_errorcode}\)%{DATA:proxy_errormessage}:)?( \[client %{IPORHOST:client}:%{POSINT:clientport}\])? %{DATA:errorcode}: %{GREEDYDATA:message}',
    'HTTPDATE': r'%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}',
    'HTTPDERROR_DATE': r'%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}',
    'HTTPDUSER': r'%{EMAILADDRESS}|%{USER}',
    'INT': r'(?:[+-]?(?:[0-9]+))',
    'IP': r'(?:%{IPV6}|%{IPV4})',
    'IPORHOST': r'(?:%{IP}|%{HOSTNAME})',
    'IPV4': r'(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])',
    'IPV6': r'((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?',
    'ISO8601_SECOND': r'(?:%{SECOND}|60)',
    'ISO8601_TIMEZONE': r'(?:Z|[+-]%{HOUR}(?::?%{MINUTE}))',
    'LOGLEVEL': r'([Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)',
    'MAC': r'(?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})',
    'MINUTE': r'(?:[0-5][0-9])',
    'MONTH': r'\b(?:Jan(?:uary|uar)?|Feb(?:ruary|ruar)?|M(?:a|ä)?r(?:ch|z)?|Apr(?:il)?|Ma(?:y|i)?|Jun(?:e|i)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|O(?:c|k)?t(?:ober)?|Nov(?:ember)?|De(?:c|z)(?:ember)?)\b',
    'MONTHDAY': r'(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])',
    'MONTHNUM': r'(?:0?[1-9]|1[0-2])',
    'MONTHNUM2': r'(?:0[1-9]|1[0-2])',
    'NONNEGINT': r'\b(?:[0-9]+)\b',
    'NOTSPACE': r'\S+',
    'NUMBER': r'(?:%{BASE10NUM})',
    'PATH': r'(?:%{UNIXPATH}|%{WINPATH})',
    'POSINT': r'\b(?:[1-9][0-9]*)\b',
    'PROG': r'[\x21-\x5a\x5c\x5e-\x7e]+',
    'QS': r'%{QUOTEDSTRING}',
    'QUOTEDSTRING': r'(?>(?<!\\)(?>"(?>\\.|[^\\"]+)+"|""|(?>\'(?>\\.|[^\']+)+\')|\'\'|(?>`(?>\\.|[^\\`]+)+`)|``))',
    'SECOND': r'(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)',
    'SPACE': r'\s*',
    'SYSLOGBASE': r'%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:',
    'SYSLOGFACILITY': r'<%{NONNEGINT:facility}.%{NONNEGINT:priority}>',
    'SYSLOGHOST': r'%{IPORHOST}',
    'SYSLOGPROG': r'%{PROG:program}(?:\[%{POSINT:pid}\])?',
    'SYSLOGTIMESTAMP': r'%{MONTH} +%{MONTHDAY} %{TIME}',
    'TIME': r'(?!<[0-9])%{HOUR}:%{MINUTE}(?::%{SECOND})(?![0-9])',
    'TIMESTAMP_ISO8601': r'%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?',
    'TTY': r'(?:/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+))',
    'TZ': r'(?:[PMCE][SD]T|UTC)',
    'UNIXPATH': r'(/([\w_%!$@:.,~-]+|\\.)*)+',
    'URI': r'%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?',
    'URIHOST': r'%{IPORHOST}(?::%{POSINT:port})?',
    'URIPARAM': r'\?[A-Za-z0-9$.+!*\'|(){},~@#%&/=:;_?\-\[\]<>]*',
    'URIPATH': r'(?:/[A-Za-z0-9$.+!*\'(){},~:;=@#%_\-]*)+',
    'URIPATHPARAM': r'%{URIPATH}(?:%{URIPARAM})?',
    'URIPROTO': r'[A-Za-z]+(\+[A-Za-z+]+)?',
    'USER': r'%{USERNAME}',
    'USERNAME': r'[a-zA-Z0-9._-]+',
    'UUID': r'[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}',
    'WINDOWSMAC': r'(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})',
    'WINPATH': r'(?>[A-Za-z]+:|\\)(?:\\[^\\?*]*)+',
    'WORD': r'\b\w+\b',
    'YEAR': r'(?>\d\d){1,2}',
    }

def logging_conf(
        level='INFO', # DEBUG
        use='stdout' # "stdout syslog" "stdout syslog file"
        ):
    import logging.config
    script_directory, script_name = os.path.split(__file__)
    logging.config.dictConfig({'version':1,'disable_existing_loggers':False,
       'formatters':{
           'standard':{'format':'%(asctime)s %(levelname)-5s %(filename)s-%(funcName)s(): %(message)s'},
           'syslogf': {'format':'%(filename)s[%(process)d]: %(levelname)-5s %(funcName)s(): %(message)s'},
           #'graylogf':{"format":"%(asctime)s %(levelname)-5s %(filename)s-%(funcName)s(): %(message)s"},
           },
       'handlers':{
           'stdout':   {'level':level,'formatter': 'standard','class':'logging.StreamHandler',         'stream': 'ext://sys.stdout'},
           'file':     {'level':level,'formatter': 'standard','class':'logging.FileHandler',           'filename': os.path.expanduser('~/.tmp/log/{}.log'.format(os.path.splitext(script_name)[0]))}, #
           'syslog':   {'level':level,'formatter': 'syslogf', 'class':'logging.handlers.SysLogHandler','address': '/dev/log', 'facility': 'user'}, # (localhost, 514), local5, ...
           #'graylog': {'level':level,'formatter': 'graylogf','class':'pygelf.GelfTcpHandler',         'host': 'log.mydomain.local', 'port': 12201, 'include_extra_fields': True, 'debug': True, '_ide_script_name':script_name},
       }, 'loggers':{'':{'handlers': use.split(),'level': level,'propagate':True}}})

FABRIC = \
    r'\A' + \
    r'\[%{BASE10NUM}m%{TIMESTAMP_ISO8601:timestamp_str} %{TZ:timezone}' + \
    r' \[%{SYSLOGPROG:module}\]' + \
    r' %{SYSLOGPROG:function}' + \
    r' -> %{NOTSPACE:loglevel}' + \
    r' %{NOTSPACE}' + \
    r' %{GREEDYDATA:message}' + \
    r'$'

ZOOKEEPER = \
    r'\A' + \
    r'(?<timestamp_str>%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND}(?:,?%{BASE10NUM})?)?%{ISO8601_TIMEZONE}?)' + \
    r' \[myid:(?<zkid_str>[^\]]*)\]' + \
    r' - %{LOGLEVEL:loglevel} *' + \
    r' \[(?<thread>[^:]*)' + \
    r':(?<classname>[^@]*)' + \
    r'@(?<line_number_str>[^\]]*)\]' + \
    r'(?:\[(?<ncd>[^\]]*)\])?' + \
    r' - (?<message>.*)' + \
    r'$'

KAFKA = \
    r'\A' + \
    r'\[(?<timestamp_str>%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND}(?:,?%{BASE10NUM})?)?%{ISO8601_TIMEZONE}?)\]' + \
    r' %{LOGLEVEL:loglevel}' + \
    r' (?<message>.*)' + \
    r' \((?<category>.*)\)' + \
    r'$'

PROMETHEUS = \
    r'\A' + \
    r'level=%{LOGLEVEL:loglevel}' + \
    r' ts=%{TIMESTAMP_ISO8601:timestamp_str}' + \
    r' caller=(?<function>[^:]*)(:(?<line_number_str>\d+))?' + \
    r' component=(?<module>[^ ]*)' + \
    r' msg="?(?<message>.*[^"])"?' + \
    r' key=(?<key>\S+/\S+)' + \
    r'$'

FLUENTD = \
    r'\A' + \
    r'%{TIMESTAMP_ISO8601:timestamp_str}' + \
    r' %{ISO8601_TIMEZONE:timezone}' + \
    r' \[%{LOGLEVEL:loglevel}\]:' + \
    r' (?<message>.*)' + \
    '$'

NGINX_STDERR = \
    r'\A' + \
    r'(?<timestamp_str>%{YEAR}/%{MONTHNUM}/%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND}))' + \
    r' \[%{LOGLEVEL:loglevel}\]' + \
    r' (?<message>.*)' + \
    '$'

NGINX_STDOUT = \
    r'\A' + \
    r'(?:%{IP:proxyip}|%{HOSTNAME:proxyhost})' + \
    r' - ' + \
    r'\[(?:%{IP:realip}|%{HOSTNAME:realhost})\]' + \
    r' - (?:-|%{HTTPDUSER:remote_user}) ' + \
    r'\[%{HTTPDATE:timestamp_str}\]'  + \
    r' "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion_str})?|%{DATA:rawrequest})"' + \
    r' %{NUMBER:status_str}' + \
    r' (?:%{NUMBER:bytes_str}|-)' + \
    r' "(?:-|(?<referer>.*?))"' + \
    r' "(?:-|(?<agent>.*?))"' + \
    r' (?:%{NUMBER:request_length_str}|-)' + \
    r' (?:%{NUMBER:request_time_str}|-)' + \
    r' \[(?<upstream_name>[^\]]*)]' + \
    r' (?:-|%{IP:upstreamip}|%{HOSTNAME:upstreamhost})' + \
    r' (?:%{NUMBER:upstream_response_length_str}|-)' + \
    r' (?:%{NUMBER:upstream_response_time_str}|-)' + \
    r' (?:%{NUMBER:upstream_response_status_str}|-)' + \
    r'(?: (?<nginx_dont_know>.*))?' + \
    r'$'

_KUBE_APISERVER = \
    r'%{WORD:verb}' + \
    r' (?<request>[^:]*)' + \
    r': \((?:%{NUMBER:request_us}[^msn]{0,2}s|%{NUMBER:request_ms}ms)\)' + \
    r' %{NUMBER:status_str}' + \
    r' \[\[(?<agent>.*?)\]' + \
    r' (?:%{IP:realip}|%{HOSTNAME:realhost})' + \
    r':%{POSINT:port}\]' + \
    r''

KUBE_APISERVER_GELF = r'\A' + _KUBE_APISERVER +'$'

KUBE_APISERVER_STDOUT = \
    r'\A' + \
    r'(?<loglevel>\w)' + \
    r'(?<timestamp_str>%{MONTHNUM}%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})(?:\.?%{BASE10NUM})?)' + \
    r' +%{POSINT:pid}' + \
    r' (?<module>[^:]+)' + \
    r'(?::(?<line_number_str>\d+))?' + \
    r'\] ' + \
    r'(?:' + _KUBE_APISERVER + '|(?<message>.*))' + \
    r'$'
    

KUBE_DASHBOARD = \
    r'\A' + \
    r'(?<timestamp_str>%{YEAR}/%{MONTHNUM}/%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND}))' + \
    r' (?<message>.*)' + \
    '$'

KUBE_OTHERS = \
    r'\A' + \
    r'(?<loglevel>\w)' + \
    r'(?<timestamp_str>%{MONTHNUM}%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})(?:\.?%{BASE10NUM})?)' + \
    r' +%{POSINT:pid}' + \
    r' (?<module>[^:]+)' + \
    r'(?::(?<line_number_str>\d+))?' + \
    r'\] (?<message>.*)' + \
    '$'

KEY_VALUE_MSG = \
    r'\bmsg="(?<message>[^"]+)'

MMDD_HH_MM_SS_SSSSSSS = \
    r'\A' + \
    r'(?<timestamp_str>%{MONTHNUM}%{MONTHDAY} %{HOUR}:%{MINUTE}:%{SECOND}\.\d{6})' + \
    '$'


def bip(pattern, message):
    grok = Grok(pattern, custom_patterns=blablaken_patterns)
    print(message)
    print(pattern)
    print(escape(pattern))
    pprint(grok.match(message))

def go(args):
    if 0:
        bip(FABRIC,
            '[36m2018-07-04 08:23:22.707 UTC [orderer/consensus/kafka/sarama] tryRefreshMetadata -> DEBU e9ient/metadata fetching metadata for all topics from broker fabric-kafka:9092'
            )
    if 0:
        bip(ZOOKEEPER,
            '2018-07-04 13:06:51,577 [myid:] - INFO  [NIOServerCxn.Factory:0.0.0.0/0.0.0.0:2181:NIOServerCnxnFactory@192] - Accepted socket connection from /127.0.0.1:5313'
            )
    if 0:
        # https://logging.apache.org/log4j/1.2/apidocs/org/apache/log4j/PatternLayout.html
        bip(KAFKA,
            '[2018-07-04 14:17:14,893] TRACE [Controller id=0] Checking need to trigger auto leader balancing (kafka.controller.KafkaController)'
            )
    if 0:
        # prometheus
        bip(PROMETHEUS,
            'level=info ts=2018-07-09T15:15:17.631189793Z caller=operator.go:396 component=alertmanageroperator msg="sync alertmanager" key=monitoring/kube-prometheus'
            )
    if 0:
        # fluentd
        bip(FLUENTD,
            '2018-07-09 15:34:19 +0000 [info]: #0 [filter_kube_metadata] stats - namespace_cache_size: 5, pod_cache_size: 6, namespace_cache_api_updates: 1389, pod_cache_api_updates: 1389, id_cache_miss: 1389'
            )
    if 0:
        bip(NGINX_STDOUT,
            #'100.96.4.0 - [100.96.4.0] - - [10/Jul/2018:12:13:25 +0000] "\x03\x00\x00/*\xE0\x00\x00\x00\x00\x00Cookie: mstshash=Administr" 400 174 "-" "-" 0 0.108 [] - - - - a14c27f3ee37022ceaf2fe35a2bd3594'
            '127.0.0.1 - [127.0.0.1] - - [10/Jul/2018:15:14:18 +0000] "GET /nginx_status/format/json HTTP/1.1" 200 3876 "-" "Go-http-client/1.1" 118 0.000 [internal] - - - - 846d9cefe1b678e5b2a41c948bf8cd64'
            #'127.0.0.1 - [127.0.0.1] - - [09/Jul/2018:15:38:48 +0000] "GET /nginx_status/format/json HTTP/1.1" 200 3867 "-" "Go-http-client/1.1" 118 0.000 [internal] - - - - a2a91d8d802596635bd4ebe19f28d6f6'
            )
    if 0:
        bip(r"\A%{IP:hehe}$",
            '1.1.1.1'
            )
    if 0:
        bip(NGINX_STDERR,
            '2018/07/10 13:12:28 [crit] 7084#7084: *381404 SSL_do_handshake() failed (SSL: error:1417D102:SSL routines:tls_process_client_hello:unsupported protocol) while SSL handshaking, client: 100.96.5.1, server: 0.0.0.0:443'
            )
    if 0:
        bip(KUBE_APISERVER_GELF,
            'GET /api: (2.002044ms) 200 [[kube-controller-manager/v1.9.3 (linux/amd64) kubernetes/d283541/system:serviceaccount:kube-system:generic-garbage-collector] 127.0.0.1:28524]'
            )
    if 1:
        bip(
            MMDD_HH_MM_SS_SSSSSSS,
            '0710 14:14:09.182939'
            )
    if 0:
        bip(KUBE_APISERVER_STDOUT,
            #'I0710 14:14:09.182939       1 wrap.go:42] GET /apis/admissionregistration.k8s.io/v1beta1/validatingwebhookconfigurations: (843.995µs) 200 [[kube-apiserver/v1.9.3 (linux/amd64) kubernetes/d283541] 127.0.0.1:17544]'
            #'I0710 14:14:09.182939       1 wrap.go:42] GET /apis/admissionregistration.k8s.io/v1beta1/validatingwebhookconfigurations: (1.23456ms) 200 [[kube-apiserver/v1.9.3 (linux/amd64) kubernetes/d283541] 127.0.0.1:17544]'
            #'I0710 14:13:58.740266       1 wrap.go:42] GET /metrics: (118.305958ms) 200 [[Prometheus/2.2.1] 172.18.10.9:50128]'
            #'I0710 15:22:16.274196       1 wrap.go:42] GET /apis/admissionregistration.k8s.io/v1alpha1/initializerconfigurations: (116.382µs) 404 [[kube-apiserver/v1.9.3 (linux/amd64) kubernetes/d283541] 127.0.0.1:40258]'
            #'I0710 15:33:30.682764    2501 server.go:796] GET /metrics: (21.410357ms) 200 [[Prometheus/2.2.1] 172.18.10.9:40616]'
            'I0711 04:46:16.436290       1 wrap.go:42] GET /apis/admissionregistration.k8s.io/v1beta1/mutatingwebhookconfigurations: (956.033µs) 200 [[kube-apiserver/v1.9.3 (linux/amd64) kubernetes/d283541] 127.0.0.1:22820]'
            #'I0711 07:55:02.555712       1 get.go:238] Starting watch for /api/v1/namespaces/monitoring/endpoints, rv=7857835 labels= fields= timeout=7m49s'
            )
    if 0:
        bip(KUBE_OTHERS,
            #'I0710 15:18:57.305271       1 pod.go:246] collected 74 pods'
            'E0710 15:40:08.569887    2501 summary.go:92] Failed to get system container stats for "/system.slice/docker.service": failed to get cgroup stats for "/system.slice/docker.service": failed to get container info for "/system.slice/docker.service": unknown container "/system.slice/docker.service"'
            )
    if 0:
        bip(KUBE_DASHBOARD,
            '2018/07/10 15:26:48 Metric client health check failed: the server could not find the requested resource (get services heapster). Retrying in 30 seconds.'
            )
    if 0:
        bip(KEY_VALUE_MSG,
                'level=info ts=2018-07-11T07:28:54.089590158Z caller=silence.go:271 component=silences msg="Maintenance done" duration=2.214298ms size=0'
            )

def escape(pattern):
    return pattern.replace('\\',r'\\').replace('"', r'\"')

def test():
    custom_patterns = dict()
    pat = '%{INT:test_int}'
    custom_patterns['mrha'] = pat

    pat2 = '%{mrha:hehe}'
    grok = Grok(pat2, custom_patterns=custom_patterns)
    text = '1024'
    m = grok.match(text)
    pprint(m)

if __name__ == '__main__':

    logging_conf()
    try:
        go(sys.argv[1:])
    except BaseException as e:
        logging.exception('oups')
        raise e

