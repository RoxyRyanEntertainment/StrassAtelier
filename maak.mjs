// Strass Atelier: bron versleutelen tot app.enc, of app.enc terug openzetten naar bron/
// node maak.mjs versleutel <code>     (bron/*.js -> app.enc)
// node maak.mjs open <code>           (app.enc -> bron/*.js)
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { webcrypto as C } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';

const FILES = ['shapes.js', 'core.js', 'trace.js', 'app.js'];
const IT = 400000;
const [mode, code] = process.argv.slice(2);
if (!mode || !code) { console.log('gebruik: node maak.mjs versleutel|open <code>'); process.exit(1); }

async function key(salt){
  const base = await C.subtle.importKey('raw', new TextEncoder().encode('strass-atelier:' + code), 'PBKDF2', false, ['deriveKey']);
  return C.subtle.deriveKey({name:'PBKDF2', salt, iterations:IT, hash:'SHA-256'}, base, {name:'AES-GCM', length:256}, false, ['encrypt', 'decrypt']);
}
if (mode === 'versleutel') {
  const json = JSON.stringify(FILES.map(n => ({n, s:readFileSync('bron/' + n, 'utf8')})));
  const salt = C.getRandomValues(new Uint8Array(16)), iv = C.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await C.subtle.encrypt({name:'AES-GCM', iv}, await key(salt), gzipSync(json, {level:9})));
  writeFileSync('app.enc', Buffer.concat([salt, iv, ct]));
  console.log('app.enc', ct.length, 'bytes');
} else {
  const b = readFileSync('app.enc'), salt = b.subarray(0, 16), iv = b.subarray(16, 28);
  const pt = await C.subtle.decrypt({name:'AES-GCM', iv}, await key(salt), b.subarray(28));
  mkdirSync('bron', {recursive:true});
  for (const f of JSON.parse(gunzipSync(Buffer.from(pt)).toString('utf8'))) writeFileSync('bron/' + f.n, f.s);
  console.log('bron/ klaar');
}
