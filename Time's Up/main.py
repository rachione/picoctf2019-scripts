import os
import paramiko
import sys
import warnings
import time


warnings.filterwarnings(action='ignore', module='.*paramiko.*')




class mySSH:
    def __init__(self, host, user, pwd):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(host, username=user, password=pwd)
        self.ssh_shell = self.ssh.invoke_shell()

    def send(self, msg):
        self.ssh_shell.send(msg+'\n')

    def getMsg(self, tick=0.5):
        msg = b''
        time.sleep(tick)
        if self.ssh_shell.recv_ready():
            msg += self.ssh_shell.recv(9999)
        print(msg.decode())
        return msg.decode()

    def connect_ssh(self):
        path = "/problems/time-s-up_3_37ba6326d772bf884eab8f28e480e580"
        self.getMsg()
        self.send('cd '+path)
        self.getMsg()
        self.send('trap "" 14 && ./times-up')
        self.send('123')
        self.getMsg()

    def close_ssh(self):
        self.ssh.close()


def main():
    myssh = mySSH('2019shell1.picoctf.com', 'mikon', 'password')
    myssh.connect_ssh()
    myssh.close_ssh()


main()
