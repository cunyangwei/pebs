import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob

if len(sys.argv) < 2:
    sys.exit("Usage: python script.py <filename>")

file_name = sys.argv[1]
data = pd.read_csv(file_name, header=None, sep=' ', names=['address', 'timestamp', 'thread_id', 'event_type'])

page_size = 4096
data['page_id'] = data['address'] // page_size

page_counts = data['page_id'].value_counts().sort_index()
page_counts = page_counts[page_counts.index > 3e10]

plt.figure(figsize=(10, 6))

page_ids = page_counts.index.values
counts = page_counts.values

plt.scatter(page_ids, counts, color='red', s=5) 






folder_path = '/home/wcy/pebs'
pattern = f"{folder_path}/accessed_addresses_*.txt"

file_list = glob.glob(pattern)

data = pd.concat((pd.read_csv(file, header=None, names=['address']) for file in file_list), ignore_index=True)

data['address'] = data['address'].apply(lambda x: int(x, 16))

data['page_id'] = data['address'] // page_size

page_counts = data['page_id'].value_counts().sort_index()

page_ids = page_counts.index.values
counts = page_counts.values

plt.scatter(page_ids, counts, color='blue', s=5) 
plt.xlabel('Logical Page ID')
plt.ylabel('Accessed Number')

plt.savefig("ana.png", format='png', dpi=300)
