const path = require('path');
const fs = require('fs');

fs.mkdirSync(path.resolve(__dirname, 'dist/browser'), { recursive: true });
fs.mkdirSync(path.resolve(__dirname, 'dist/node'), { recursive: true });

fs.copyFileSync(
  path.resolve(__dirname, 'libs/chacha20poly1305.js'),
  path.resolve(__dirname, 'dist/browser/chacha20poly1305.js')
);

fs.copyFileSync(
  path.resolve(__dirname, 'libs/chacha20poly1305.js'),
  path.resolve(__dirname, 'dist/node/chacha20poly1305.js')
);

var script = fs.readFileSync(
  path.resolve(__dirname, 'dist/browser/netcode.js')
);
script += `
var {aead_encrypt,aead_decrypt,getRandomBytes}=require('./chacha20poly1305');
`;
var entryFile = path.resolve(__dirname, 'dist/node/netcode.js');
fs.writeFileSync(entryFile, script);
console.log('successfully export', entryFile);
