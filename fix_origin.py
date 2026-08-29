import re

target_text = """            btnNewTab.onclick = () => createTab(window.location.origin + '/');
            
            createTab(window.location.origin + '` + targetUrl + `');"""

replacement_text = """            btnNewTab.onclick = () => createTab('` + window.location.origin + `/');
            
            createTab('` + window.location.origin + targetUrl + `');"""

for file in ["void.html", "public/void.html", "public/index.html"]:
    with open(file, "r") as f:
        content = f.read()
    if target_text in content:
        content = content.replace(target_text, replacement_text)
        with open(file, "w") as f:
            f.write(content)
        print(f"Fixed {file}")
    else:
        print(f"Target not found in {file}")
