#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   sonar.py
@Time    :   2021/10/13 17:18:33
@Author  :   wind
'''

from sonarqube import SonarQubeClient
import requests
import json

class SonarQube:
    def __init__(self, url, username="admin", password="xxxxxx") -> None:
        username = username
        password = password
        sonarqube_url = url
        self.client = SonarQubeClient(username=username, password=password,
                                      sonarqube_url=sonarqube_url)

    def getProjects(self):
        """ 获取项目列表"""
        projects = list(self.client.projects.search_projects())
        return projects


    def getMeasures(self, component):
        """ 获取项目各个参数数据"""
        metricKeys = "alert_status,bugs,,vulnerabilities,security_rating,code_smells,duplicated_lines_density,coverage,ncloc"
        measures = []
        measures.append(self.client.measures.get_component_with_specified_measures(
            component, metricKeys))
        return measures


    def getBugs(self, project_name):
        s = SonarQube(url='http://192.168.151.107:9000/')
        all_project_info = s.getProjects()
        for project_info in all_project_info:
            component = project_info.get("key")
            pname = s.getMeasures(component)[0]['component']['key']
            if pname == project_name:
                # measures为无序列表位置每次位置不固定，只能循环确定
                metrics = s.getMeasures(component)[0]['component']['measures']
                for metric in metrics:
                    if metric['metric'] == 'bugs':
                        bugs_num = metric["value"]
                return bugs_num


    def createProject(self, project_name):
        url = 'http://192.168.151.107:9000/api/projects/create'
        headers = {'Content-Type': 'application/json;charset=utf-8'}
        body = {
            "project": {
                "key": "project-key",
                "name": project_name,
                "qualifier": "TRK"
            }
            }
        requests.post(url, json.dumps(body), headers=headers)


# if __name__ == '__main__':
#     s = SonarQube(url='http://192.168.151.107:9000/')
#     s.createProject("test1")
# pip install pip install python-sonarqube-api
