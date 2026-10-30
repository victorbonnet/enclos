import collections
import json
import sys
seen = collections.Counter()
for line in open(sys.argv[1]):
    e = json.loads(line)
    seen[(e.get("host"), e.get("port"), e.get("verdict"), e.get("reason", ""))] += 1
for (h, p, v, r), n in sorted(seen.items(), key=str):
    print(f"- {h}:{p} {v} {r} ({n})")
