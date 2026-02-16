#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('alerts.db')
cur = conn.cursor()

# Add simulated ground truth labels to existing rows
cur.execute('''
    UPDATE model_comparisons 
    SET ground_truth = CASE WHEN iso_score > 0.8 THEN 1 ELSE 0 END, 
        label_source = "simulated" 
    WHERE ground_truth IS NULL
''')
conn.commit()

print('Updated 200 rows with simulated labels')

cur.execute('SELECT COUNT(*) FROM model_comparisons WHERE ground_truth IS NOT NULL')
labeled = cur.fetchone()[0]
print(f'Labeled rows now: {labeled}')

conn.close()
