import re
import json

new_version = '4.6.5'
old_version = '4.6.4'

# 1. Update package.json
with open('package.json', 'r') as f:
    pkg = json.load(f)
pkg['version'] = new_version
with open('package.json', 'w') as f:
    json.dump(pkg, f, indent=2)
    f.write('\n')

# 2. Update HTML files
for filepath in ['void.html', 'public/void.html', 'public/index.html']:
    with open(filepath, 'r') as f:
        content = f.read()
    
    # We replace var APP_VER = '...'; with var APP_VER = '4.6.5';
    content = re.sub(rf"var APP_VER = '{old_version}';", f"var APP_VER = '{new_version}';", content)
    
    with open(filepath, 'w') as f:
        f.write(content)

print(f"Bumped version to {new_version}")
