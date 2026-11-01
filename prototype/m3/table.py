"""Joins probe.py's outputs, one file per mode, into a Markdown table: one row
per probe, one column per mode. A cell is the result, then the detail cut
short. Used by the check scripts.

    python3 -I table.py 'host=host.tsv' 'bwrap only=bwrap.tsv' ...
"""

import sys

cols, rows, order = [], {}, []
for arg in sys.argv[1:]:
    label, _, path = arg.partition("=")
    cols.append(label)
    try:
        lines = open(path).read().splitlines()
    except OSError:
        lines = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        spec, result = parts[0], parts[1]
        detail = parts[2] if len(parts) > 2 else ""
        if spec not in rows:
            rows[spec] = {}
            order.append(spec)
        cell = result + (f" ({detail[:60]})" if detail else "")
        rows[spec][label] = cell.replace("|", "\\|")

print("| probe | " + " | ".join(cols) + " |")
print("| --- |" + " --- |" * len(cols))
for spec in order:
    cells = [rows[spec].get(c, "not run") for c in cols]
    print(f"| `{spec}` | " + " | ".join(cells) + " |")
