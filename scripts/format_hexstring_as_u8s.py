#!/usr/bin/env python3

import sys

PER_LINE = 8

string = sys.argv[1]

entries = [string[i : i + 2] for i in range(0, len(string), 2)]

for i in range(len(string) // 16):
    print(", ".join([f"0x{j}" for j in entries[8 * i : 8 * (i + 1)]]) + ",")
