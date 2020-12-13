import binascii
from pwn import *
import sys
from struct import pack

BINARY = './times-up-again'
context.terminal = ['tmux', 'splitw', '-h']


def attach_gdb(sh):
    gdb.attach(sh)


def P32(v):
    return pack('I', v)


def P64(v):
    return pack('Q', v)


def deHex(v):
    return binascii.unhexlify(v)[::-1]


def start():
    if args["REMOTE"]:
        s = ssh(host='2019shell1.picoctf.com',
                user='mikon', password="password")
        sh = s.process(
            'times-up-again', cwd='/problems/time-s-up--again-_2_55710a2388cfe35ec1afa8221b3f1ded')
    else:
        sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh

def handler(signum, frame):
    print('Signal handler called with signal', signum)
    raise OSError("Couldn't open device!")

def main():
    sh = start()
    def send(x): return sh.sendlineafter('\n', x)

    

    sh.interactive()


if __name__ == '__main__':
    main()
