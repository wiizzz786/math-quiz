const template = `
  const match1 = iframeUrl.match(/\/p\/([^/?]+)/);
  const match2 = iframeUrl.match(/\\/p\\/([^/?]+)/);
`;

console.log("Template 1:", template.includes("match1 = iframeUrl.match(/\/p\/([^/?]+)/)"));
console.log("Resulting template string:");
console.log(template);
