#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib
import json
import os
import sys
from idecore import credentials
import requests
import re
import argparse
import logging
import textwrap
import mrgrok 
from mrgrok import *

from pprint import pprint, pformat

logger = logging.getLogger(__name__)
kwargs_blabla = dict(
    parenturl = 'https://graylog.mikrocrap.net/api',
    user = 'mur',
    pass_source = 'uoeu bnuaoeb nbtuaeo',
    )
STREAM0 = u'000000000000000000000001'

def logging_conf(
        level='INFO', # DEBUG
        use='stdout' # "stdout syslog" "stdout syslog file"
        ):
    import logging.config
    logging.config.dictConfig({'version':1,'disable_existing_loggers':False,
       'formatters':{
           'standard':{'format':'%(asctime)s %(levelname)-5s %(filename)s-%(funcName)s(): %(message)s'},
           'syslogf': {'format':'%(filename)s[%(process)d]: %(levelname)-5s %(funcName)s(): %(message)s'},
           },
       'handlers':{
           'stdout': {'level':level,'formatter': 'standard','class':'logging.StreamHandler','stream': 'ext://sys.stdout'},
           'file':   {'level':level,'formatter': 'standard','class':'logging.FileHandler','filename': '/tmp/tarace.log'}, #
           'syslog': {'level':level,'formatter': 'syslogf', 'class':'logging.handlers.SysLogHandler','address': '/dev/log', 'facility': 'user'}, # (localhost, 514), local5, ...
       }, 'loggers':{'':{'handlers': use.split(),'level': level,'propagate':True}}})

def req(suburl, parenturl='https://gl.we.are.from.the.center:443/api', verify=False, user='adminmur', password=None, pass_source='passide', method=None, data=None, proxies=None, headers=None):
    while suburl.startswith('/'): suburl = suburl[1:]
    url = '{}/{}'.format(parenturl, suburl)
    if method is None:
        method = 'GET' if data is None else 'POST'
    if data is not None:
        if isinstance(data, dict):
            data = json.dumps(data)
        if headers is None:
            headers = {}
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
    if password is None and pass_source is not None:
        password = credentials.get(pass_source)
    r = requests.request(
        method,
        url,
        headers=headers,
        data=data,
        proxies=proxies,
        verify=verify,
        auth=(user, password)
        )
    try:
        return r.json()
    except:
        logger.warn('Failed to convert to json')
        return r.text

def dump_streams():
    r = req('streams')['streams']
    #pprint(r[0])
    pprint(r)
    r = sorted(r, key=lambda s: s['description'].lower())
    for s in r:
        print(s['description'])

def stream_id_by_title(title):
    return stream_by_title(title)['id']
def saved_search_id_by_title(title):
    return saved_search_by_title(title)['id']
def pipeline_rule_id_by_title(title, **kwargs):
    return pipeline_rule_by_title(title, **kwargs)['id']
def pipeline_pipeline_id_by_title(title, **kwargs):
    return pipeline_pipeline_by_title(title, **kwargs)['id']
def pipeline_rule_update(title, updateH, **kwargs):
    if not isinstance(updateH, dict): raise BaseException('not a dict')
    cH = pipeline_rule_by_title(title, **kwargs)
    uH = dict(
        description=cH['description'],
        source=cH['source'],
        title=cH['title'],
        )
    uH.update(updateH)
    return req(
        'plugins/org.graylog.plugins.pipelineprocessor/system/pipelines/rule/{}'.format(cH['id']),
        method='PUT',
        data = uH,
        **kwargs
        )

def pipeline_rule_create_or_update(title, updateH, **kwargs):
    if not isinstance(updateH, dict): raise BaseException('not a dict')
    url = 'plugins/org.graylog.plugins.pipelineprocessor/system/pipelines/rule'
    try:
        cH = pipeline_rule_by_title(title, **kwargs)
        method = 'PUT'
        url = '{}/{}'.format(url, cH['id'])
        uH = dict(
            description=cH['description'],
            source=cH['source'],
            title=cH['title'],
            )
    except StopIteration:
        method = 'POST'
        uH = dict(
            description='auto description for rule {}'.format(title),
            source='rule "{}"\nwhen false\nend;'.format(title),
            title=title
            )
    uH.update(updateH)
    r = req(
        url,
        method=method,
        data = uH,
        **kwargs
        )
    return r

GIT_DIR = os.path.expanduser('~/git/blabla/infra/graylog/')
def pipeline_rule_create_or_update_wrapper(source, *pattern): #, **kwargs):
    source = textwrap.dedent(source).strip()
    n = re.search(r'rule "([^"]+)', source).group(1)
    source = re.sub(r'\bthen\b', 'then\n    set_field("rule-{}", 1);'.format(n), source)
    print(source)
    if len(pattern) > 0:
        patterns = map(mrgrok.escape, pattern)
        source = source.format(*patterns)
    source = source.replace('PREFIX_', 'app_')
    r = pipeline_rule_create_or_update(n, dict(source=source), **kwargs_blabla) #**kwargs)
    if not isinstance(r, dict) or r['errors'] is not None:
        pprint(r)
        raise BaseException("bip")
    pprint(r)
    dp = os.path.join(GIT_DIR, 'rule')
    fp = os.path.join(dp, n)
    if os.path.isdir(dp):
        with open(fp, 'w') as f:
            f.write(source)


def pipeline_pipeline_create_or_update(title, updateH, stream_id=STREAM0, **kwargs):
    if not isinstance(updateH, dict): raise BaseException('not a dict')
    url = 'plugins/org.graylog.plugins.pipelineprocessor/system/pipelines/pipeline'
    try:
        cH = pipeline_pipeline_by_title(title, **kwargs)
        method = 'PUT'
        url = '{}/{}'.format(url, cH['id'])
        uH = dict(
            description=cH['description'],
            #stages=cH['stages'],
            title=cH['title'],
            )
    except StopIteration:
        method = 'POST'
        uH = dict(
            description='auto description for pipeline {}'.format(title),
            #stages=[],
            title=title
            )

    uH.update(updateH)
    r = req(
        url,
        method=method,
        data = uH,
        **kwargs
        )
    if isinstance(r, list):
        pprint(r)
        raise BaseException("errors in pipeline creation")
    pprint(r)

    i = pipeline_pipeline_id_by_title(title, **kwargs)
    url = 'plugins/org.graylog.plugins.pipelineprocessor/system/pipelines/connections/to_pipeline'
    r = req(
        url,
        method='POST',
        data = dict(
            stream_ids=[stream_id],
            pipeline_id=i,
            ),
        **kwargs
        )
    pprint(r)


def stream_by_title(title):
    return next(r for r in req('streams')['streams'] if r['title'] == title)
def saved_search_by_title(title):
    return next(r for r in req('search/saved')['searches'] if r['title'] == title)
def pipeline_rule_by_title(title, **kwargs):
    return next(r for r in req('plugins/org.graylog.plugins.pipelineprocessor/system/pipelines/rule', **kwargs) if r['title'] == title)
def pipeline_pipeline_by_title(title, **kwargs):
    return next(r for r in req('plugins/org.graylog.plugins.pipelineprocessor/system/pipelines/pipeline', **kwargs) if r['title'] == title)

def aggregate_by_name(name):
    proxies = None
    proxies = p
    return next(r for r in req( 'plugins/org.graylog.plugins.aggregates/rules', proxies=proxies)['rules'] if r['name'] == name)


def go(args):
    if 1:
        k = kwargs_blabla

        pipeline_pipeline_create_or_update_wrapper(r"""
            pipeline "greytoken-pipeline"
            stage 0 match either
                rule "alertmanager-prometheus-svc0"
                rule "docker-systemd"
                rule "fabric"
                rule "fluentd"
                rule "kafka"
                rule "kube-apiserver-gelf"
                rule "kube-apiserver-stdout"
                rule "kube-dashboard"
                rule "kube-others"
                rule "kubelet"
                rule "nginx-stderr"
                rule "nginx-stdout"
                rule "prometheus-operator"
                rule "zookeeper"
            stage 1 match either
                rule "mr-expand-loglevel"
                rule "line_number-to-long"
            stage 900 match all
                rule "timestampwhen"
            stage 901 match either
                rule "timestamp-mmdd-hh-mm-ss-SSSSSSS"
            end
            """)


        pipeline_rule_create_or_update_wrapper(r"""
                rule "timestamp-mmdd-hh-mm-ss-SSSSSSS"
                when grok(pattern: "{}", value: to_string($message.PREFIX_timestamp_str), only_named_captures: true).matches == true
                then
                    set_field("PREFIX_timestamp", parse_date(concat(to_string(now().year), to_string($message.PREFIX_timestamp_str)), "YYYYMMdd HH:mm:ss.SSSSSS", "en-US"));
                    remove_field("PREFIX_timestamp_str");
                end;
                """, MMDD_HH_MM_SS_SSSSSSS)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "line_number-to-long"
            when has_field("PREFIX_line_number_str")
            then
                set_field("PREFIX_line_number", to_long($message.PREFIX_line_number_str));
                remove_field("PREFIX_line_number_str");
            end;
            """)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "kube-dashboard"
            when $message.container_name == "kubernetes-dashboard"
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_timestamp_str), "yyyy/MM/dd HH:mm:ss", "en-US"));
                remove_field("PREFIX_timestamp_str");
            end;
            """, KUBE_DASHBOARD)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "kube-others"
            when $message.container_name == "exporter-kube-state"
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_timestamp",                parse_date(concat(to_string(now().year), to_string($message.PREFIX_timestamp_str)), "YYYYMMdd HH:mm:ss.SSSSSS", "en-US"));
                remove_field("PREFIX_timestamp_str");
            end;
            """, KUBE_OTHERS)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "kube-apiserver-stdout"
            when ($message.container_name == "kube-apiserver" and
                  $message.stream         == "stdout"
                 )
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_timestamp",                parse_date(concat(to_string(now().year), to_string($message.PREFIX_timestamp_str)), "YYYYMMdd HH:mm:ss.SSSSSS", "en-US"));
                remove_field("PREFIX_timestamp_str");
                set_field("PREFIX_status",                   to_long(   $message.PREFIX_status_str));                    remove_field("PREFIX_status_str");
            end;
            """, KUBE_APISERVER_STDOUT)
                #set_field("PREFIX_timestamp_debug",                concat(to_string(now().year), to_string($message.PREFIX_timestamp_str)));

        pipeline_rule_create_or_update_wrapper(r"""
            rule "alertmanager-prometheus-svc0"
            when ($message.container_name == "alertmanager" ||
                  $message.container_name == "prometheus"   ||
                  $message.container_name == "svc-0"
                 )
            then
                set_fields(fields: key_value(value:to_string($message.message), trim_key_chars: "\"", trim_value_chars:"\""), prefix: "PREFIX_");
                rename_field("PREFIX_level", "PREFIX_loglevel");
                rename_field("PREFIX_msg", "PREFIX_message");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_ts), "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'", "en-US"));
                remove_field("PREFIX_ts");
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
            end;
            """, KEY_VALUE_MSG)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "docker-systemd"
            when ($message.tag == "docker.systemd" and has_field("MESSAGE"))
            then
                set_field("message", $message.MESSAGE);
                set_fields(fields: key_value(value:to_string($message.MESSAGE), trim_key_chars: "\"", trim_value_chars:"\""), prefix: "PREFIX_");
                rename_field("PREFIX_level", "PREFIX_loglevel");
                rename_field("PREFIX_msg", "PREFIX_message");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_time), "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'", "en-US"));
                remove_field("PREFIX_time");
                set_fields(fields: grok(pattern: "{}", value: to_string($message.MESSAGE), only_named_captures: true), prefix: "PREFIX_");
            end;
            """, KEY_VALUE_MSG)
                #set_fields(fields: key_value(value:to_string($message.MESSAGE), delimiters: "\" ", trim_key_chars: "\"", trim_value_chars:"\""), prefix: "PREFIX_");

        pipeline_rule_create_or_update_wrapper(r"""
            rule "kube-apiserver-gelf"
            when ($message.tag == "kube-apiserver"
                 )
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_status",                   to_long(   $message.PREFIX_status_str));                    remove_field("PREFIX_status_str");
                rename_field("severity", "PREFIX_loglevel");
            end;
            """, KUBE_APISERVER_GELF)


        pipeline_rule_create_or_update_wrapper(r"""
            rule "kubelet"
            when ($message.tag == "kubelet" and has_field("MESSAGE"))
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.MESSAGE), only_named_captures: true), prefix: "PREFIX_");
                set_fields(fields: grok(pattern: "{}", value: to_string($message.MESSAGE), only_named_captures: true), prefix: "PREFIX_");
                set_field("message", $message.MESSAGE);
                set_field("PREFIX_status",                   to_long(   $message.PREFIX_status_str));                    remove_field("PREFIX_status_str");
            end;
            """, KUBE_APISERVER_STDOUT, KUBE_OTHERS)
                #set_field("PREFIX_timestamp",                parse_date(concat(to_string(now().year), to_string($message.PREFIX_timestamp_str)), "YYYYMMdd HH:mm:ss.SSSSSS", "en-US"));
                #remove_field("PREFIX_timestamp_str");
        pipeline_rule_create_or_update_wrapper(r"""
            rule "timestampwhen"
            when (has_field("PREFIX_timestamp_str") &&
                  !has_field("PREFIX_timestamp")
                  )
            then
            end;""")

        pipeline_rule_create_or_update_wrapper(r"""
            rule "fluentd"
            when $message.container_name == "fluentd"
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_timestamp_str), "yyyy-MM-dd HH:mm:ss", "en-US", to_string($message.PREFIX_timezone)));
                remove_field("PREFIX_timestamp_str");
            end;
            """, FLUENTD)


        pipeline_rule_create_or_update_wrapper(r"""
            rule "prometheus-operator"
            when $message.container_name == "prometheus-operator"
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_timestamp_str), "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'", "en-US"));
                remove_field("PREFIX_timestamp_str");
            end;
            """, PROMETHEUS)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "fabric"
            when ($message.container_name == "fabric-orderer-container" ||
                  $message.container_name == "fabric-nodejs-container"  ||
                  $message.container_name == "fabric-peer-container"
                  )
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_timestamp_str), "yyyy-MM-dd HH:mm:ss.SSS", "en-US", to_string($message.PREFIX_timezone)));
                remove_field("PREFIX_timestamp_str");
            end;
            """, FABRIC)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "nginx-stderr"
            when ($message.container_name == "nginx-ingress-controller" and
                  $message.stream         == "stderr")
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_timestamp_str), "yyyy/MM/dd HH:mm:ss", "en-US"));
                remove_field("PREFIX_timestamp_str");
            end;
            """, NGINX_STDERR)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "nginx-stdout"
            when ($message.container_name == "nginx-ingress-controller" and
                  $message.stream         == "stdout")
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_request_time",             to_double( $message.PREFIX_request_time_str));              remove_field("PREFIX_request_time_str");
                set_field("PREFIX_httpversion",              to_double( $message.PREFIX_httpversion_str));               remove_field("PREFIX_httpversion_str");
                set_field("PREFIX_request_length",           to_long(   $message.PREFIX_request_length_str));            remove_field("PREFIX_request_length_str");
                set_field("PREFIX_status",                   to_long(   $message.PREFIX_status_str));                    remove_field("PREFIX_status_str");
                set_field("PREFIX_bytes",                    to_long(   $message.PREFIX_bytes_str));                     remove_field("PREFIX_bytes_str");
                set_field("PREFIX_upstream_response_time",   to_double( $message.PREFIX_upstream_response_time_str));    remove_field("PREFIX_upstream_response_time_str");
                set_field("PREFIX_upstream_response_length", to_long(   $message.PREFIX_upstream_response_length_str));  remove_field("PREFIX_upstream_response_length_str");
                set_field("PREFIX_upstream_status",          to_long(   $message.PREFIX_upstream_response_status));      remove_field("PREFIX_upstream_response_status");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_timestamp_str), "dd/MMM/yyyy:HH:mm:ss' 'Z", "en-US")); remove_field("PREFIX_timestamp_str");
            end;
            """, NGINX_STDOUT)
        """     to_ip causes messages to be dropped, can't find a way to have it work
                set_field("PREFIX_upstreamip",               to_ip(    $message.PREFIX_upstreamip_str));                remove_field("PREFIX_upstreamip_str");
                set_field("PREFIX_proxyip",                  to_ip(    $message.PREFIX_proxyip_str));                   remove_field("PREFIX_proxyip_str");
                set_field("PREFIX_realip",                   to_ip(    $message.PREFIX_realip_str));                    remove_field("PREFIX_realip_str");
        """

        pipeline_rule_create_or_update_wrapper(r"""
            rule "mr-expand-loglevel"
            when has_field("PREFIX_loglevel")
            then
                let s = to_string($message.PREFIX_loglevel);
                set_field("PREFIX_loglevel",     lookup_value("mra", concat("loglevel-",    s), $message.PREFIX_loglevel));
                set_field("PREFIX_loglevel_int", to_long(lookup_value("mra", concat("loglevelint-", s), "-1")));
            end;
            """) # https://raw.githubusercontent.com/shK3Bq4d/stdenv/stdenv/gt/a.csv

        pipeline_rule_create_or_update_wrapper(r"""
            rule "zookeeper"
            when ($message.container_name == "zookeeper" ||
                  $message.container_name == "zookeeper-server"
                 )
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_timestamp_str), "yyyy-MM-dd HH:mm:ss,SSS", "en-US"));
                remove_field("PREFIX_timestamp_str");
                set_field("PREFIX_zkid",           to_long(   $message.PREFIX_zkid_str));
                remove_field("PREFIX_zkid_str");
            end;
            """, ZOOKEEPER)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "kafka"
            when $message.container_name == "kafka-broker"
            then
                set_fields(fields: grok(pattern: "{}", value: to_string($message.message), only_named_captures: true), prefix: "PREFIX_");
                set_field("PREFIX_timestamp",                parse_date(to_string($message.PREFIX_timestamp_str), "yyyy-MM-dd HH:mm:ss,SSS", "en-US"));
                remove_field("PREFIX_timestamp_str");
            end;
            """, KAFKA)

        pipeline_rule_create_or_update_wrapper(r"""
            rule "httpversion"
            when has_field("PREFIX_httpversion_str")
            then
                set_field("PREFIX_httpversion", to_double($message.PREFIX_httpversion_str));
                remove_field("PREFIX_httpversion_str");
            end;
            """)
        pipeline_rule_create_or_update_wrapper(r"""
            rule "nginx-httpversion"
            when has_field("PREFIX_httpversion_str")
            then
                set_field("PREFIX_httpversion", to_double($message.PREFIX_httpversion_str));
                remove_field("PREFIX_httpversion_str");
            end;
            """)


def pipeline_pipeline_create_or_update_wrapper(source):
    source = textwrap.dedent(source)
    n = re.search(r'pipeline "([^"]+)', source).group(1)
    pprint(pipeline_pipeline_create_or_update(n, dict(source=source), **kwargs_blabla))
    dp = os.path.join(GREYTOKEN_GIT_DIR, 'pipeline')
    fp = os.path.join(dp, n)
    if os.path.isdir(dp):
        with open(fp, 'w') as f:
            f.write(source)

if __name__ == '__main__':
    reload(sys)
    sys.setdefaultencoding('utf-8')

    logging_conf()
    try:
        go(sys.argv[1:])
    except BaseException as e:
        logging.exception('oups')
        raise e

