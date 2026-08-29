var targetUrl = '/v?q=hello';
var textContent = `
let foo = 1;
createTab(window.location.origin + '` + targetUrl + `');
`;
console.log(textContent);
