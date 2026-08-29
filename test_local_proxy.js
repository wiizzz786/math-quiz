import { spawn } from 'child_process';
import axios from 'axios';

function encryptUrl(str) {
  var key = "NoodalMathKey2026";
  var out = [];
  for (var i = 0; i < str.length; i++) {
    var k = key.charCodeAt(i % key.length);
    var code = str.charCodeAt(i) ^ k ^ ((i * 13 + 7) & 0xFF);
    out.push(String.fromCharCode(code));
  }
  return btoa(out.join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '') + '.www.securly.com';
}

const target = 'https://www.bing.com/favicon.ico';
const encrypted = encryptUrl(target);
const proxyUrl = `http://localhost:8080/p/${encrypted}`;

console.log("Encrypted URL:", encrypted);
console.log("Proxy URL:", proxyUrl);

// Start the server
const server = spawn('node', ['server.js'], {
  cwd: '/Users/Aadhyanchinnam/Downloads/void/math-quiz',
  env: { ...process.env, PORT: '8080' }
});

server.stdout.on('data', async (data) => {
  const output = data.toString();
  console.log("Server STDOUT:", output);
  if (output.includes('running on')) {
    // Server is ready, make request!
    try {
      console.log("Fetching from proxy...");
      const res = await axios.get(proxyUrl, {
        responseType: 'arraybuffer',
        headers: {
          'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'x-void-dest': 'image',
          'x-void-mode': 'no-cors',
          'x-void-site': 'cross-site'
        }
      });
      console.log("Response status:", res.status);
      console.log("Response headers:", res.headers);
      console.log("Response body size:", res.data.length);
    } catch (err) {
      console.error("Fetch failed:", err.message);
      if (err.response) {
        console.error("Error headers:", err.response.headers);
        console.error("Error body size:", err.response.data.length);
      }
    } finally {
      server.kill();
      process.exit(0);
    }
  }
});

server.stderr.on('data', (data) => {
  console.error("Server STDERR:", data.toString());
});
