import sys, subprocess


template = """
def get_rss():
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) / 1024
    return 0.0

mem_before = get_rss()

import MODULE_NAME

print(f"{ get_rss() - mem_before:.2f}")
"""

print("\nRAM Footprint on Import (Native Linux /proc/self/status):\n")

for mod in ("jwt", "webtoken"):
    code = template.replace("MODULE_NAME", mod)
    
    result = subprocess.run((sys.executable, "-c", code), capture_output=True, text=True)
    
    if result.returncode:
        print(f"Error running {mod}: {result.stderr.strip()}")
    else:
        print(f"{mod}: {' ' * (10 -len(mod))} {result.stdout.strip()} MB")