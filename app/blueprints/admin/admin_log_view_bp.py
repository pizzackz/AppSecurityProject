import re
import ast
import pandas as pd
import sys

infile = "infile.log"

pat1 = re.compile(r'\{.*\}')
pat2 = re.compile(r'\(.*\)')

all_data = []
with open(infile, 'r') as f:
    for line in f:
        if 'type' not in line:
            continue

        v = ast.literal_eval(pat1.search(line).group(0))
        t = ast.literal_eval(pat2.search(line).group(0))[0]
        all_data.append({'time': line.split(' INFO ')[0].strip('"') ,'type': t, **v})

df = pd.DataFrame(all_data)
print(df)