import re

# 1. Update the tab element creation to include the favicon image
target_tab_creation = """              const titleEl = document.createElement('span');
              titleEl.textContent = 'Loading...';
              titleEl.style.overflow = 'hidden';
              titleEl.style.textOverflow = 'ellipsis';
              
              const closeBtn = document.createElement('span');
              closeBtn.className = 'tab-close';
              closeBtn.textContent = '✕';
              closeBtn.onclick = (e) => {
                e.stopPropagation();
                closeTab(id);
              };
              
              tabEl.appendChild(titleEl);
              tabEl.appendChild(closeBtn);"""

replacement_tab_creation = """              const favEl = document.createElement('img');
              favEl.src = '` + window.location.origin + `/favicon.svg';
              favEl.style.width = '14px';
              favEl.style.height = '14px';
              favEl.style.marginRight = '6px';
              favEl.style.borderRadius = '2px';
              favEl.style.flexShrink = '0';

              const titleEl = document.createElement('span');
              titleEl.textContent = 'Loading...';
              titleEl.style.overflow = 'hidden';
              titleEl.style.textOverflow = 'ellipsis';
              
              const closeBtn = document.createElement('span');
              closeBtn.className = 'tab-close';
              closeBtn.textContent = '✕';
              closeBtn.onclick = (e) => {
                e.stopPropagation();
                closeTab(id);
              };
              
              tabEl.appendChild(favEl);
              tabEl.appendChild(titleEl);
              tabEl.appendChild(closeBtn);"""

# 2. Update about:blank initialization to set the browser tab favicon
target_win_init = """        var win = window.open('about:blank', '_blank');
        if (win) {
          win.document.title = 'Classes';
          win.document.body.innerHTML = `"""

replacement_win_init = """        var win = window.open('about:blank', '_blank');
        if (win) {
          win.document.title = 'Classes';
          var link = win.document.createElement('link');
          link.type = 'image/svg+xml';
          link.rel = 'shortcut icon';
          link.href = '` + window.location.origin + `/favicon.svg';
          win.document.head.appendChild(link);
          
          win.document.body.innerHTML = `"""

for file in ["void.html", "public/void.html", "public/index.html"]:
    with open(file, "r") as f:
        content = f.read()
    
    modified = False
    if target_tab_creation in content:
        content = content.replace(target_tab_creation, replacement_tab_creation)
        modified = True
    if target_win_init in content:
        content = content.replace(target_win_init, replacement_win_init)
        modified = True
        
    if modified:
        with open(file, "w") as f:
            f.write(content)
        print(f"Updated favicons in {file}")
    else:
        print(f"No match found in {file}")
