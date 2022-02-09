#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   sshclient.py
@Time    :   2021/10/15 14:30:33
@Author  :   wind 
'''

import subprocess
import paramiko

def cmdout(cmd):
    # ip = str(cmdout("ifconfig | grep -C 1 eth0 | grep -v grep | grep inet | awk '{print $2}'")).strip()
    try:
        out_text = subprocess.check_output(cmd, shell=True).decode('utf-8')
    except subprocess.CalledProcessError as e:
        out_text = e.output.decode('utf-8')
    return out_text


def sshexec_tool(ip, username,  port, password, cmd):
    ssh = paramiko.SSHClient()
    # 允许连接不在know_hosts文件中的主机
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # 建立连接
    # ssh.connect(ip, username="xxx", port=22, password="xxx")
    ssh.connect(ip, username=username, port=port, password=password)
    # 使用这个连接执行命令
    # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd, get_pty=True, timeout=3600000)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd, get_pty=True)
    # 获取输出
    print(ssh_stdout.read())
    # 关闭连接
    ssh.close()


def cmdout(cmd):
    try:
        out_text = subprocess.check_output(cmd, shell=True).decode('utf-8')
    except subprocess.CalledProcessError as e:
        out_text = e.output.decode('utf-8')
    return out_text
