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

const server = spawn('node', ['server.js'], {
  cwd: '/Users/Aadhyanchinnam/Downloads/void/math-quiz',
  env: { ...process.env, PORT: '8080' }
});

server.stdout.on('data', async (data) => {
  const output = data.toString();
  if (output.includes('running on')) {
    try {
      console.log("Fetching HPImageArchive from proxy...");
      const apiTarget = 'https://www.bing.com/HPImageArchive.aspx?format=js&idx=0&n=1&mkt=en-US';
      const apiEnc = encryptUrl(apiTarget);
      const apiRes = await axios.get(`http://localhost:8080/p/${apiEnc}`, {
        headers: { 'user-agent': 'Mozilla/5.0' }
      });
      
      const resJson = apiRes.data;
      console.log("HPImageArchive response:", resJson);
      
      if (resJson.images && resJson.images[0]) {
        const imageUrl = 'https://www.bing.com' + resJson.images[0].url;
        console.log("Current daily wallpaper URL:", imageUrl);
        
        const imgEnc = encryptUrl(imageUrl);
        console.log("Fetching image from proxy...");
        const imgRes = await axios.get(`http://localhost:8080/p/${imgEnc}`, {
          responseType: 'arraybuffer',
          headers: {
            'user-agent': 'Mozilla/5.0',
            'x-void-dest': 'image',
            'x-void-mode': 'no-cors',
            'x-void-site': 'cross-site'
          }
        });
        
        console.log("Image response status:", imgRes.status);
        console.log("Image response Content-Type:", imgRes.headers['content-type']);
        console.log("Image response body size:", imgRes.data.length);
      }
    } catch (err) {
      console.error("Test failed:", err.message);
      if (err.response) {
        console.error("Error body:", Buffer.from(err.response.data).toString('utf8'));
      }
    } finally {
      server.kill();
      process.exit(0);
    }
  }
});
