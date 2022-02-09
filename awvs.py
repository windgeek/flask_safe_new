#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   awvs.py
@Time    :   2021/10/08 15:36:57
@Author  :   wind 
'''

import json
import ssl
import urllib.request
import os
import ast

ssl._create_default_https_context = ssl._create_unverified_context

#os.environ['http_proxy'] = 'http://127.0.0.1:8080'
#os.environ['https_proxy'] = 'https://127.0.0.1:8080'

IP = '10.1.1.102'
API_KEY = 'xxxxxxx'


def create_target(address, description, int_criticality):
    url = 'https://' + IP + ':3443/api/v1/targets'
    # url = 'awvs-scan.iyou.com/api/v1/targets'

    headers = {"X-Auth": API_KEY, "content-type": "application/json",
               'User-Agent': 'curl/7.53.1'}
    values = {
        'address': address,
        'description': description,
        'criticality': int_criticality,
    }
    data = bytes(json.dumps(values), 'utf-8')
    request = urllib.request.Request(url, data, headers)
    html = urllib.request.urlopen(request).read().decode('utf-8')
    return html


def get_target_list():
    url = 'https://' + IP + ':3443/api/v1/targets'
    # url = 'https://awvs-scan.iyou.com/api/v1/targets'
    headers = {"X-Auth": API_KEY, "content-type": "application/json",
               'User-Agent': 'curl/7.53.1'}
    request = urllib.request.Request(url=url, headers=headers)
    html = urllib.request.urlopen(request).read().decode('utf-8')
    return html


def get_result(adress):
    url = 'https://' + IP + ':3443/api/v1/targets'
    # url = 'https://awvs-scan.iyou.com/api/v1/targets'
    headers = {"X-Auth": API_KEY, "content-type": "application/json",
               'User-Agent': 'curl/7.53.1'}
    request = urllib.request.Request(url=url, headers=headers)
    html = urllib.request.urlopen(request).read().decode('utf-8')
    data = json.loads(html)
    # print(data, type(data))
    results = data["targets"]
    # print(results, type(results))
    for r in results:
        padress = r["address"]
        if padress == adress:
            severity_counts = r["severity_counts"]
    return severity_counts


def profiles_list():
    url = 'https://' + IP + ':3443/api/v1/scanning_profiles'
    headers = {"X-Auth": API_KEY, "content-type": "application/json",
               'User-Agent': 'curl/7.53.1'}
    request = urllib.request.Request(url=url, headers=headers)
    html = urllib.request.urlopen(request).read().decode('utf-8')
    return html


def start_target(target_id, profile_id, schedule):
    url = 'https://' + IP + ':3443/api/v1/scans'

    headers = {"X-Auth": API_KEY, "content-type": "application/json",
               'User-Agent': 'curl/7.53.1'}
    values = {
        'target_id': target_id,
        'profile_id': profile_id,
        'schedule': schedule,
    }
    data = bytes(json.dumps(values), 'utf-8')
    request = urllib.request.Request(url, data, headers)
    html = urllib.request.urlopen(request).read().decode('utf-8')
    return html


def stop_target(target_id):
    url = 'https://' + IP + ':3443/api/v1/scans/' + target_id + '/abort'
    headers = {"X-Auth": API_KEY, "content-type": "application/json",
               'User-Agent': 'curl/7.53.1'}
    request = urllib.request.Request(url=url, headers=headers)
    html = urllib.request.urlopen(request).read().decode('utf-8')
    print(html)


def target_status(target_id):
    url = 'https://' + IP + ':3443/api/v1/scans/' + target_id
    headers = {"X-Auth": API_KEY, "content-type": "application/json",
               'User-Agent': 'curl/7.53.1'}
    request = urllib.request.Request(url=url, headers=headers)
    html = urllib.request.urlopen(request).read().decode('utf-8')
    print(html)


def get_target_result(target_id, scan_session_id):
    url = 'https://' + IP + ':3443/api/v1/scans/' + target_id + \
        '/results/' + scan_session_id + '/vulnerabilities '
    headers = {"X-Auth": API_KEY, "content-type": "application/json",
               'User-Agent': 'curl/7.53.1'}
    request = urllib.request.Request(url=url, headers=headers)
    html = urllib.request.urlopen(request).read().decode('utf-8')
    print(html)


# if __name__ == '__main__':
    # print(get_target_list())
    # print(create_target("172.28.26.125:80", "DMP的SaaS版安全屋服务", "10"))
    # target_status('d61afd6d-649c-4dd1-952b-6fc1f278e104')
    # start_target('aa4f6b6a-0bcd-4a8d-8881-e1957ed80616', '')
    # get_result("https://ra.iyou.com")
