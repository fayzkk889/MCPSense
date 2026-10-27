import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { product } from './content.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), 'dist');
const receipt = { origin:product.origin, checked_at:new Date().toISOString(), pages:[], assets:[], headers:null, missing:null };
const hash = data => createHash('sha256').update(data).digest('hex');
const heading = html => html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/)?.[1].replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim();
async function files(directory) {
  const items = await readdir(directory,{withFileTypes:true});
  return (await Promise.all(items.map(item=>item.isDirectory()?files(join(directory,item.name)):[join(directory,item.name)]))).flat();
}
for (const file of await files(root)) {
  const name = relative(root,file).replaceAll('\\','/');
  if (name === '_headers') continue; // Cloudflare parses this; verify its effects below.
  const path = '/' + name.replace(/index\.html$/,'');
  const response = await fetch(product.origin+path,{signal:AbortSignal.timeout(15000),credentials:'omit'});
  assert.equal(response.status,200,path);
  const live = Buffer.from(await response.arrayBuffer());
  const expected = await readFile(file);
  if (name.endsWith('.html')) {
    const html = live.toString('utf8');
    assert.equal(heading(html),heading(expected.toString('utf8')),`Stale heading: ${path}`);
    assert.ok(html.includes('<main id="main">'),`Missing content: ${path}`);
    const csp = response.headers.get('content-security-policy') || '';
    for (const directive of ["default-src 'self'","object-src 'none'","base-uri 'none'","form-action 'none'"]) assert.ok(csp.includes(directive),`Missing ${directive}: ${path}`);
    assert.ok(!csp.includes('unsafe-inline')&&!csp.includes('unsafe-eval'),`Unsafe policy: ${path}`);
    assert.equal(response.headers.get('x-content-type-options'),'nosniff',path);
    assert.equal(response.headers.get('x-frame-options'),'DENY',path);
    assert.ok(response.headers.get('cache-control')?.includes('must-revalidate'),path);
    receipt.pages.push({path,status:response.status,heading:heading(html)});
    if (path==='/') receipt.headers=Object.fromEntries(['content-security-policy','cache-control','x-content-type-options','x-frame-options','permissions-policy'].map(key=>[key,response.headers.get(key)]));
  } else if (name === 'robots.txt') {
    const actual = live.toString('utf8').trimEnd();
    const original = expected.toString('utf8').trimEnd();
    assert.ok(actual.endsWith(original),'Site crawler rules/sitemap are missing');
    if (actual!==original) assert.ok(actual.includes('# BEGIN Cloudflare Managed content')&&actual.includes('# END Cloudflare Managed Content'),'Unknown robots.txt modification');
    receipt.assets.push({path,comparison:actual===original?'exact':'original rules preserved after Cloudflare managed prefix',sha256:hash(live)});
  } else {
    assert.ok(live.equals(expected),`Asset bytes differ: ${path}`);
    receipt.assets.push({path,comparison:'exact',sha256:hash(live)});
  }
}
const missing = await fetch(product.origin+'/__mcpsense_verification_missing__',{signal:AbortSignal.timeout(15000),credentials:'omit'});
assert.equal(missing.status,404,'Unknown routes must return 404');
assert.equal(heading(await missing.text()),heading(await readFile(join(root,'404.html'),'utf8')),'Custom 404 page');
receipt.missing=404;
console.log(JSON.stringify(receipt,null,2));
