#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by wind on 12/1/20

from flask import Flask
from flask import request, abort
import time
import logging
import awvs
import sshclient
import nessus_new



app = Flask(__name__)


# post请求格式json 例子：{"address":"https://ra.iyou.com"}
@app.route('/awvs', methods=["POST"])
def getAwvs():
    data = request.json
    address = data['address']
    try:
        severity_counts = awvs.get_result(address)
    except Exception as e:
        logger.debug(e)
    return severity_counts


# post请求格式json 例子：{"address":"https://ra.iyou.com"}
@app.route('/nikto', methods=["POST"])
def getNikto():
    data = request.json
    address = data['address']
    ptime = time.strftime('%Y-%m-%d-%H:%M:%S')
    fname = address.replace('https://', '').replace('http://', '')
    fhtml = "http://172.28.9.180:65330/{}-{}.html".format(fname, ptime)
    cmd = 'cd /data/nikto-master/program/; ./nikto.pl -h {} -o ./results/{}-{}.html -F html'.format(
        address, fname, ptime)
    try:
        sshclient.cmdout(cmd)
    except Exception as e:
        logger.debug(e)
    return fhtml


# sonar-scanner \
#   -Dsonar.projectKey=test \
#   -Dsonar.sources=. \
#   -Dsonar.host.url=http://192.168.151.107:9000 \
#   -Dsonar.login=xxxxxxx
# post请求格式json 例子：{"project_name":"xxxx", "git_address":"http://mp.iyou.com/xx.xx/xxx.git", "pom_dir":"/"}
@app.route('/sonarcmd', methods=["POST"])
def getGit():
    data = request.json
    projectname = data['project_name']
    git_address = data['git_address'].replace(
        'https://', '').replace('http://', '')
    pom_dir = data["pom_dir"]
    git_file = git_address.split('/')[-1].replace(".git", "")
    purl = 'http://sonar.iyou.com/dashboard?id={}'.format(projectname)
    apom_dir = "/data/git_packages/{}{}".format(projectname, pom_dir)
    # mp.iyou.com/bin.zou/mp_intelligence.git
    p_dict = {"ig": "xxx", "cu": "xxxxxx"}
    p_token = p_dict[projectname]
    acmd = 'cd /data/git_packages; rm -rf {}; git clone http://root:xxxxxx@{}'.format(
        git_file, git_address)
    bcmd = 'cd {}; mkdir -p target/classes; sonar-scanner -Dsonar.projectKey={} -Dsonar.sources=. -Dsonar.host.url=http://192.168.151.107:9000 -Dsonar.login={} -Dsonar.java.binaries=target/classes; exit 0'.format(
        apom_dir, projectname, p_token)
    # print(bcmd)
    # ccmd = 'echo "{}" > /data/git_packages/tmp.sh && /bin/sh /data/git_packages/tmp.sh > /tmp/tmp.log'.format(bcmd)
    # print(ccmd)
    try:
        sshclient.cmdout(acmd)
        sshclient.cmdout(bcmd)
    except Exception as e:
        logger.debug(e)
    return purl


# post请求格式json 例子：{"host":"172.28.9.180"}
@app.route('/nessus', methods=["POST"])
def getNessus():
    print("OK")
    data = request.json
    host = data['host']
    ptime = time.strftime('%Y-%m-%d-%H-%M-%S')
    fname = "{}_{}".format(host, ptime)
    # nessus_new.login(username, password)
    print('Adding new scan.')
    policies = nessus_new.get_policies()
    policy_id = policies['Basic Network Scan']
    scan_data = nessus_new.add('Host Scan', 'Create a new scan with API', host, policy_id)
    scan_id = scan_data['id']
    print('Launching new scan.')
    scan_uuid = nessus_new.launch(scan_id)
    history_ids = nessus_new.get_history_ids(scan_id)
    history_id = history_ids[scan_uuid]
    while nessus_new.status(scan_id, history_id) != 'completed':
        time.sleep(5)
    print('Exporting the completed scan.')
    # file_id = nessus_new.export(scan_id, history_id)
    acmd = "mkdir -p nessus_report/{}; cd nessus_report/{}/; ../../nessus_report.py -i 172.28.5.228 -u admin -p xxx@ -s {} -f 2".format(fname, fname, scan_id)
    purl = "http://172.28.9.180:65530/{}/{}.html".format(fname, fname)
    sshclient.cmdout(acmd)
    newname = sshclient.cmdout("cd ./nessus_report/{}/; ls -l|awk '{{print $9}}'".format(fname)).strip()
    bcmd = "cd ./nessus_report/{}/; mv {} {}.html".format(fname, newname, fname)
    print(bcmd)
    sshclient.cmdout(bcmd)
    return purl


# 日志模块
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
fileHandler = logging.FileHandler('safe.log', mode='w', encoding='UTF-8')
fileHandler.setLevel(logging.NOTSET)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)


if __name__ == '__main__':
    app.run(debug=True)

# 直接启动的话，默认5000端口
# 用gunicorn启动 nohup gunicorn -b 0.0.0.0:23333 app:app > gunicorn.log 2>&1 &
# gunicorn -w 2 -b 0.0.0.0:23333 app:app
# 加超时 单位为s
# gunicorn -w 2 -b 0.0.0.0:23333 app:app --timeout 3600


# 原生启动
# export FLASK_DEBUG=1
# nohup /data/python3.9/bin/flask run --host=0.0.0.0 --port=23333 &


# gun详细配置启动
# nohup gunicorn -c gunicorn_config.py app:app &


# http://sonar.iyou.com/
