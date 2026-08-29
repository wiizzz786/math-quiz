import re

def fix_html_file(filepath, new_version='4.5.5'):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Update APP_VER
    content = re.sub(r"var APP_VER = '.*?';", f"var APP_VER = '{new_version}';", content)
    
    # 2. Add buttons if missing
    if 'id="btn-check-update"' not in content:
        buttons_html = """
    <button type="button" id="btn-check-update">Check GitHub Update</button>
    
    <div id="update-actions" style="display:none; margin-top:10px;">
      <button type="button" id="btn-manual-apply">Apply Instant Update</button>
      <button type="button" id="btn-direct-download">Download new version</button>
    </div>
"""
        content = content.replace('<div style="display:none;">\n      <button type="button" id="btn-open-settings">',
                                  buttons_html + '\n    <div style="display:none;">\n      <button type="button" id="btn-open-settings">')

    # 3. Add JS functions if missing
    if 'function checkGitHubUpdate()' not in content:
        js_functions = """
      function checkGitHubUpdate() {
        log('Checking for updates...');
        updStatusEl.textContent = 'Status: Checking GitHub repo...';
        fetch('https://raw.githubusercontent.com/' + GITHUB_REPO + '/main/package.json?t=' + Date.now())
          .then(function(res) { return res.ok ? res.json() : null; })
          .then(function(pkg) {
            if (!pkg || !pkg.version) {
              updStatusEl.textContent = 'Status: Unable to fetch GitHub release info.';
              log('Update check failed.');
              return;
            }
            log('GitHub Remote Version: v' + pkg.version + ' (Local: v' + APP_VER + ')');
            if (isNewerVer(pkg.version, APP_VER)) {
              updStatusEl.textContent = '[UPDATE AVAILABLE: v' + pkg.version + '] Press Apply Instant Update or Download!';
              log('>>> NEW UPDATE FOUND: v' + pkg.version + ' <<<');
            } else {
              updStatusEl.textContent = 'System is fully up to date (v' + APP_VER + ').';
              log('System up to date (v' + APP_VER + ').');
            }
          })
          .catch(function(err) {
            updStatusEl.textContent = 'Status: Update check failed (' + err.message + ')';
            log('Update check error: ' + err.message);
          });
      }

      function applyManualUpdate() {
        log('[MANUAL UPDATE]: Fetching raw ' + location.pathname.split('/').pop() + ' from GitHub main branch...');
        updStatusEl.textContent = '[UPDATE IN PROGRESS]: Fetching latest code from GitHub...';
        var filename = location.pathname.split('/').pop() || 'index.html';
        if (!filename.includes('.html')) filename = 'index.html';
        var rawUrl = 'https://raw.githubusercontent.com/' + GITHUB_REPO + '/main/' + (filename === 'index.html' ? 'public/index.html' : filename) + '?t=' + Date.now();
        fetch(rawUrl)
          .then(function(res) {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return res.text();
          })
          .then(function(html) {
            log('[MANUAL UPDATE SUCCESS]: Received fresh code (' + html.length + ' bytes).');
            updStatusEl.textContent = '[UPDATE APPLIED]: Reloading client...';
            try {
              document.open();
              document.write(html);
              document.close();
              log('[MANUAL UPDATE COMPLETE]: Client updated and reloaded with latest code!');
            } catch(e) {
              window.location.href = window.location.pathname + '?v=' + Date.now();
            }
          })
          .catch(function(err) {
            log('[MANUAL UPDATE ERROR]: Failed to fetch raw update (' + err.message + ').');
            updStatusEl.textContent = '[UPDATE FAILED]: ' + err.message;
          });
      }

      function directDownloadFile() {
        log('[DIRECT DOWNLOAD]: Fetching latest code from GitHub for file download...');
        updStatusEl.textContent = '[DOWNLOAD]: Preparing download file...';
        var filename = location.pathname.split('/').pop() || 'index.html';
        if (!filename.includes('.html')) filename = 'index.html';
        var rawUrl = 'https://raw.githubusercontent.com/' + GITHUB_REPO + '/main/' + (filename === 'index.html' ? 'public/index.html' : filename) + '?t=' + Date.now();
        fetch(rawUrl)
          .then(function(res) {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return res.text();
          })
          .then(function(html) {
            var blob = new Blob([html], { type: 'text/html;charset=utf-8' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            log('[DIRECT DOWNLOAD SUCCESS]: File downloaded directly to your device!');
            updStatusEl.textContent = '[DOWNLOAD COMPLETE]: File saved to device!';
          })
          .catch(function(err) {
            log('[DIRECT DOWNLOAD ERROR]: ' + err.message);
            updStatusEl.textContent = '[DOWNLOAD FAILED]: ' + err.message;
          });
      }
"""
        # We need to insert this before pollForUpdates
        content = content.replace('      function pollForUpdates() {', js_functions + '\n      function pollForUpdates() {')
        
    # 4. Add Event listeners if missing
    if 'manualCheckBtn.addEventListener' not in content:
        listeners = """
      if (manualCheckBtn) manualCheckBtn.addEventListener('click', checkGitHubUpdate);
      if (manualApplyBtn) manualApplyBtn.addEventListener('click', applyManualUpdate);
      if (directDownloadBtn) directDownloadBtn.addEventListener('click', directDownloadFile);
      var btnCheckUpd = document.getElementById('btn-check-update');
      if (btnCheckUpd) btnCheckUpd.addEventListener('click', function() {
        checkGitHubUpdate();
        var ua = document.getElementById('update-actions');
        if (ua) ua.style.display = 'block';
      });
"""
        content = content.replace('      // Check immediately on load, then every 5 minutes', listeners + '\n      // Check immediately on load, then every 5 minutes')
        # If it doesn't have pollForUpdates, it's public/void.html or public/index.html which doesn't have the "Check immediately" comment
        if listeners not in content:
             content = content.replace('      var acTimer = null;', listeners + '\n      var acTimer = null;')

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

fix_html_file('void.html')
fix_html_file('public/void.html')
fix_html_file('public/index.html')
print("Done fixing HTML files")
