# Import necessary libraries
import angr
import claripy
from pwn import *

# Define the target address to reach in the program (found using Ghidra)
TARGET = 0x00403370

# Create symbolic characters (24 characters) for the input
chars = [claripy.BVS(f"c_{i}", size=8) for i in range(24)]

# Concatenate the symbolic characters to form the input
flag = claripy.Concat(*chars)

# Create an Angr project for the binary file "cracksymb"
proj = angr.Project("./cracksymb")

# Create an initial state for symbolic execution with the symbolic input as stdin
initial_state = proj.factory.entry_state(stdin=flag)

# Add addresses to avoid to the simulation manager because they are not valid paths
initial_state.options.add(angr.options.LAZY_SOLVES)

# Add constraints to the symbolic characters to ensure they are within valid ASCII range (0x20 to 0x7e) 0x20 is space and 0x7e is ~ and all characters in between are printable
for char in chars:
    initial_state.solver.add(char >= 0x20)
    initial_state.solver.add(char <= 0x7e)

# Create a simulation manager with the initial state
simgr = proj.factory.simulation_manager(initial_state)

# Use symbolic execution to explore possible paths in the program with the goal of reaching the target address
simgr.explore(find=TARGET)

# If a path leading to the target address is found
if simgr.found:
    solution = simgr.found[0].solver.eval(
        flag, cast_to=bytes)  # Get the corresponding input
    print("Found:", solution.decode('utf-8'))  # Print the input
