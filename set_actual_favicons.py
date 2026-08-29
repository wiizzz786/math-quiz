import re

target_script = """          var script = win.document.createElement('script');
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
              
              const favEl = document.createElement('img');
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
            }"""

replacement_script = """          var script = win.document.createElement('script');
          script.textContent = `
            function D(encoded) {
              try {
                let b64 = encoded;
                const tldIndex = b64.lastIndexOf(".");
                if (tldIndex > 0) b64 = b64.substring(0, tldIndex);
                b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
                while (b64.length % 4) b64 += "=";
                const raw = atob(b64);
                const key = "NoodalMathKey2026";
                let dec = [];
                for (var i = 0; i < raw.length; i++) {
                  var k = key.charCodeAt(i % key.length);
                  var code = raw.charCodeAt(i) ^ k ^ ((i * 13 + 7) & 0xFF);
                  dec.push(String.fromCharCode(code));
                }
                return dec.join('');
              } catch(e) {
                return '';
              }
            }

            function updateBrowserFavicon(src) {
              try {
                let link = document.querySelector("link[rel*='icon']") || document.createElement('link');
                link.type = 'image/x-icon';
                link.rel = 'shortcut icon';
                link.href = src;
                document.head.appendChild(link);
              } catch(e) {}
            }

            let tabIdCounter = 0;
            const tabBar = document.getElementById('tab-bar');
            const iframesContainer = document.getElementById('iframes');
            const btnNewTab = document.getElementById('btn-new-tab');

            function createTab(url) {
              const id = 'tab-' + (++tabIdCounter);
              
              const tabEl = document.createElement('div');
              tabEl.className = 'tab';
              tabEl.id = 'ui-' + id;
              
              let domain = '';
              try {
                const match = url.match(/[?&]q=([^&]+)/);
                if (match) {
                  const decrypted = D(decodeURIComponent(match[1]));
                  if (decrypted) {
                    domain = new URL(decrypted).hostname;
                  }
                }
              } catch(e) {}
              
              const favEl = document.createElement('img');
              favEl.src = domain ? ('https://www.google.com/s2/favicons?domain=' + domain + '&sz=32') : '` + window.location.origin + `/favicon.svg';
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
              tabEl.appendChild(closeBtn);
              
              tabBar.insertBefore(tabEl, btnNewTab);
              
              const iframe = document.createElement('iframe');
              iframe.id = 'frame-' + id;
              iframe.src = url;
              iframesContainer.appendChild(iframe);
              
              tabEl.onclick = () => activateTab(id);

              iframe.onload = () => {
                try {
                  const iframeUrl = iframe.contentWindow.location.href;
                  const match = iframeUrl.match(/\\/p\\/([^/?]+)/) || iframeUrl.match(/\\/pe\\/([^/?]+)/);
                  if (match) {
                    const decrypted = D(match[1]);
                    if (decrypted) {
                      const domain = new URL(decrypted).hostname;
                      favEl.src = 'https://www.google.com/s2/favicons?domain=' + domain + '&sz=32';
                      if (tabEl.classList.contains('active')) {
                        updateBrowserFavicon(favEl.src);
                      }
                    }
                  }
                } catch(e) {}
              };
              
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
              
              if (tabEl) {
                tabEl.classList.add('active');
                const img = tabEl.querySelector('img');
                if (img && img.src) {
                  updateBrowserFavicon(img.src);
                }
              }
              if (iframeEl) iframeEl.classList.add('active');
            }"""

for file in ["void.html", "public/void.html", "public/index.html"]:
    with open(file, "r") as f:
        content = f.read()
    if target_script in content:
        content = content.replace(target_script, replacement_script)
        with open(file, "w") as f:
            f.write(content)
        print(f"Updated script in {file}")
    else:
        print(f"Target not found in {file}")
