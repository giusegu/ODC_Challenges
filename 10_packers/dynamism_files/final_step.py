# i have the equation x ^ a = b to solve for x

results = [0x2648a0c1cd54abaa, 0x3c46afcfde54b5ab, 0x3178e2e5d05ba8a5, 0x3c78b7d5cd6ab2a3,
           0x1740a2d6cc6aa2a4, 0x265ea7e5c75ab5aa, 0x3c4e9cc9cb4298ed, 0x35189cded854af93]

key = 0x4827c3baaa35c7cc

flag = []

for i in range(len(results)):
    flag.append(results[i] ^ key)

# convert each flag element into a list of bytes and then append them
flag = [list(flag[i].to_bytes(8, byteorder='little'))
        for i in range(len(flag))]
flag = [x for y in flag for x in y]

print(flag)

# convert the flag into char
flag = [chr(x) for x in flag]

# join the flag
flag = ''.join(flag)

print(flag)

# flag{congratulationz_!_you_got_the_flag_from_dyn!_was_it_hard_?}
