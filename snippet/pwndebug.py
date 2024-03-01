from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    # ssh = ssh("zerocool", "192.168.64.3")
    # r = ssh.process(" ./leakers")
    r = process("./multistage")
    gdb.attach(r, """
                 c
                  """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 2003)

r.interactive()
