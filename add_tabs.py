import os

target_block = """        var win = window.open('about:blank', '_blank');
        if (win) {
          win.document.title = 'Classes';
          win.document.body.style.margin = '0';
          win.document.body.style.height = '100vh';
          win.document.body.style.overflow = 'hidden';
          var iframe = win.document.createElement('iframe');
          iframe.style.border = 'none';
          iframe.style.width = '100vw';
          iframe.style.height = '100vh';
          iframe.style.margin = '0';
          iframe.src = window.location.origin + targetUrl;
          win.document.body.appendChild(iframe);
        } else {
          window.location.href = targetUrl;
        }"""

replacement_block = """        var win = window.open('about:blank', '_blank');
        if (win) {
          win.document.title = 'Classes';
          win.document.body.innerHTML = `
            <style>
              body { margin: 0; display: flex; flex-direction: column; height: 100vh; overflow: hidden; font-family: 'Times New Roman', Times, serif; }
              #tab-bar { display: flex; background: #eee; border-bottom: 1px solid #000; padding: 4px 8px; gap: 4px; align-items: center; overflow-x: auto; flex-shrink: 0; }
              .tab { padding: 4px 12px; border: 1px solid #000; background: #fff; cursor: pointer; display: flex; gap: 6px; align-items: center; max-width: 200px; white-space: nowrap; overflow: hidden; font-size: 14px; user-select: none; }
              .tab.active { background: #ddd; font-weight: bold; box-shadow: inset 0 1px 3px rgba(0,0,0,0.1); }
              .tab-close { cursor: pointer; font-weight: bold; margin-left: auto; padding-left: 8px; color: #555; }
              .tab-close:hover { color: #000; }
              .new-tab { cursor: pointer; padding: 4px 10px; border: 1px solid #000; background: #fff; font-weight: bold; font-size: 16px; user-select: none; }
              .new-tab:hover { background: #eee; }
              #iframes { flex: 1; position: relative; }
              iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none; display: none; }
              iframe.active { display: block; }
            </style>
            <div id="tab-bar">
              <div class="new-tab" id="btn-new-tab" title="New Tab">+</div>
            </div>
            <div id="iframes"></div>
          `;
          
          var script = win.document.createElement('script');
          script.textContent = `
            let tabIdCounter = 0;
            const tabBar = document.getElementById('tab-bar');
            const iframesContainer = document.getElementById('iframes');
            const btnNewTab = document.getElementById('btn-new-tab');

            function createTab(url) {
              const id = 'tab-' + (++tabIdCounter);
              
              const tabEl = document.createElement('div');
              tabEl.className = 'tab';
              tabEl.id = 'ui-' + id;
              
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
              
              tabEl.appendChild(titleEl);
              tabEl.appendChild(closeBtn);
              
              tabBar.insertBefore(tabEl, btnNewTab);
              
              const iframe = document.createElement('iframe');
              iframe.id = 'frame-' + id;
              iframe.src = url;
              iframesContainer.appendChild(iframe);
              
              tabEl.onclick = () => activateTab(id);
              
              setInterval(() => {
                try {
                  if (iframe.contentDocument && iframe.contentDocument.title) {
                    titleEl.textContent = iframe.contentDocument.title;
                  }
                } catch(e) {}
              }, 1000);
              
              activateTab(id);
            }

            function activateTab(id) {
              document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
              document.querySelectorAll('iframe').forEach(f => f.classList.remove('active'));
              
              const tabEl = document.getElementById('ui-' + id);
              const iframeEl = document.getElementById('frame-' + id);
              
              if (tabEl) tabEl.classList.add('active');
              if (iframeEl) iframeEl.classList.add('active');
            }

            function closeTab(id) {
              const tabEl = document.getElementById('ui-' + id);
              const iframeEl = document.getElementById('frame-' + id);
              
              const wasActive = tabEl.classList.contains('active');
              
              if (tabEl) tabEl.remove();
              if (iframeEl) iframeEl.remove();
              
              if (wasActive) {
                const remainingTabs = document.querySelectorAll('.tab');
                if (remainingTabs.length > 0) {
                  const lastTabId = remainingTabs[remainingTabs.length - 1].id.replace('ui-', '');
                  activateTab(lastTabId);
                } else {
                  window.close();
                }
              }
            }

            btnNewTab.onclick = () => createTab(window.location.origin + '/');
            
            createTab(window.location.origin + '` + targetUrl + `');
          `;
          win.document.body.appendChild(script);
        } else {
          window.location.href = targetUrl;
        }"""

for file in ["void.html", "public/void.html", "public/index.html"]:
    with open(file, "r") as f:
        content = f.read()
    if target_block in content:
        content = content.replace(target_block, replacement_block)
        with open(file, "w") as f:
            f.write(content)
        print(f"Updated {file}")
    else:
        print(f"Target block not found in {file}")
