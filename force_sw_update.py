import re

# 1. Update bootSequence service worker registration
target_register_sw = """      if ("serviceWorker" in navigator) {
        var swTld = localStorage.getItem("void_tld") || ".www.securly.com";
        navigator.serviceWorker.register("/sw.js?tld=" + encodeURIComponent(swTld))"""

replacement_register_sw = """      if ("serviceWorker" in navigator) {
        var swTld = localStorage.getItem("void_tld") || ".www.securly.com";
        navigator.serviceWorker.register("/sw.js?tld=" + encodeURIComponent(swTld) + "&v=" + APP_VER)"""

# 2. Update settings save TLD button service worker registration
target_save_tld = """if('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js?tld=' + encodeURIComponent(v)); }"""
replacement_save_tld = """if('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js?tld=' + encodeURIComponent(v) + '&v=' + APP_VER); }"""

for file in ["void.html", "public/void.html", "public/index.html"]:
    with open(file, "r") as f:
        content = f.read()
    
    modified = False
    if target_register_sw in content:
        content = content.replace(target_register_sw, replacement_register_sw)
        modified = True
    if target_save_tld in content:
        content = content.replace(target_save_tld, replacement_save_tld)
        modified = True
        
    if modified:
        with open(file, "w") as f:
            f.write(content)
        print(f"Updated SW force update in {file}")
    else:
        print(f"No match found in {file}")
