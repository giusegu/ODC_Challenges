from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./revmem")
    gdb.attach(r, f"""
        set args {"abc"}
        break strncmp
        c
    """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 2003)

# r.send(b"abc")

r.interactive()
