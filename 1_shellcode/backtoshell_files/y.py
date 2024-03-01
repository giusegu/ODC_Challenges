from pwn import *

# r = remote("127.0.0.1", 4000)

# input("wait")
# shellcode = b" *90"*20

# r.send(shellcode)
# r.interactive()

context.terminal = ['tmux', 'splitw', '-h']

r = process("./backtoshell")
gdb.attach(r, """
# b * 0×004000b0
# b ×0×4000DD
c
""")

input("wait")
r.interactive()
