import re

target_block = """      const headers = new Headers(req.headers);
      headers.set('x-void-dest', req.headers.get('sec-fetch-dest') || '');
      headers.set('x-void-mode', req.headers.get('sec-fetch-mode') || '');
      headers.set('x-void-site', req.headers.get('sec-fetch-site') || '');"""

replacement_block = """      const headers = new Headers(req.headers);
      headers.set('x-void-dest', req.destination || '');
      headers.set('x-void-mode', req.mode || '');
      headers.set('x-void-site', req.mode === 'navigate' ? 'none' : 'cross-site');"""

for file in ["sw.js", "public/sw.js"]:
    with open(file, "r") as f:
        content = f.read()
    if target_block in content:
        content = content.replace(target_block, replacement_block)
        with open(file, "w") as f:
            f.write(content)
        print(f"Fixed {file}")
    else:
        print(f"Target not found in {file}")
