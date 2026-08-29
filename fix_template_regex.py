import re

# We read and replace using raw strings to prevent python escaping
target = r"const match = iframeUrl.match(/\/p\/([^/?]+)/) || iframeUrl.match(/\/pe\/([^/?]+)/);"
replacement = r"const match = iframeUrl.match(/\\/p\\/([^/?]+)/) || iframeUrl.match(/\\/pe\\/([^/?]+)/);"

for file in ["void.html", "public/void.html", "public/index.html"]:
    with open(file, "r") as f:
        content = f.read()
    if target in content:
        content = content.replace(target, replacement)
        with open(file, "w") as f:
            f.write(content)
        print(f"Fixed template regex in {file}")
    else:
        print(f"Target not found in {file}")
