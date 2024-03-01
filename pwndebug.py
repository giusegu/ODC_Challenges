from pwn import *

context. terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    ssh = ssh("acidburn", "192.168.56.104")
    r = ssh.process(" ./leakers")
    gdb.attach(r, """
                 # b *0×00401255
                 # """)
    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2010)
