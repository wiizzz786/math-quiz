import axios from 'axios';

async function test() {
  const targetUrl = 'https://www.bing.com/th?id=OHR.OysterCatchers_EN-US7091667087_1920x1080.jpg';
  
  const axiosRes = await axios({
    url: targetUrl,
    method: 'GET',
    responseType: 'arraybuffer',
    maxRedirects: 5,
    validateStatus: () => true,
    decompress: true
  });

  console.log("Original Content-Type:", axiosRes.headers['content-type']);
  console.log("Original headers keys:", Object.keys(axiosRes.headers));
}

test();
