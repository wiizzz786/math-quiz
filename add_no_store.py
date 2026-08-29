import re

target = "fetch('https://raw.githubusercontent.com/' + GITHUB_REPO + '/main/package.json?t=' + Date.now())"
replacement = "fetch('https://raw.githubusercontent.com/' + GITHUB_REPO + '/main/package.json?t=' + Date.now(), { cache: 'no-store' })"

for file in ["void.html", "public/void.html", "public/index.html"]:
    with open(file, "r") as f:
        content = f.read()
    if target in content:
        content = content.replace(target, replacement)
        with open(file, "w") as f:
            f.write(content)
        print(f"Added no-store to {file}")
    else:
        print(f"No match in {file}")
