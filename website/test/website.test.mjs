import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { releaseState, compareVersions, versionParts } from '../src/releases.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
execFileSync(process.execPath, [join(root,'build.mjs')]);
const dist = join(root,'dist');
async function files(dir) {
  const entries = await readdir(dir,{withFileTypes:true});
  return (await Promise.all(entries.map(x=>x.isDirectory()?files(join(dir,x.name)):[join(dir,x.name)]))).flat();
}
const output = await files(dist);
const htmlFiles = output.filter(x=>x.endsWith('.html'));

test('every published page has a title, description, language, one main heading and accessible navigation', async () => {
  assert.ok(htmlFiles.length >= 8);
  for (const file of htmlFiles) {
    const html = await readFile(file,'utf8');
    assert.match(html,/<html lang="en">/,file);
    assert.match(html,/<title>[^<]+<\/title>/,file);
    assert.match(html,/<meta name="description" content="[^"]+">/,file);
    assert.equal((html.match(/<h1[ >]/g)||[]).length,1,file);
    assert.match(html,/<main id="main">/,file);
    assert.match(html,/class="skip-link" href="#main"/,file);
    assert.match(html,/aria-controls="site-nav"/,file);
    assert.doesNotMatch(html,/href="(?:#|javascript:[^"]*|)"/,file);
  }
});

test('all internal links, fragments, scripts and styles resolve in the upload folder', async () => {
  let checked = 0;
  for (const file of htmlFiles) {
    const html = await readFile(file,'utf8');
    const sourcePath = '/' + file.slice(dist.length+1).replaceAll('\\','/');
    for (const [,raw] of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
      const url = new URL(raw.replaceAll('&amp;','&'),`https://mcpsense.site${sourcePath}`);
      if (url.origin !== 'https://mcpsense.site') continue;
      let target = resolve(dist,'.'+url.pathname);
      if ((await stat(target)).isDirectory()) target = join(target,'index.html');
      await stat(target);
      if (url.hash) {
        const targetHtml = await readFile(target,'utf8');
        assert.ok(targetHtml.includes(`id="${decodeURIComponent(url.hash.slice(1))}"`),`${file}: missing ${raw}`);
      }
      checked++;
    }
  }
  assert.ok(checked > 100);
  const app = await readFile(join(dist,'assets/app.js'),'utf8');
  for (const [,path] of app.matchAll(/from '([^']+)'/g)) await stat(resolve(dist,'assets',path));
});

test('release display requires two valid, matching public release channels', () => {
  const github = {tag_name:'v0.4.1',draft:false,prerelease:false};
  assert.deepEqual(releaseState({version:'0.4.1'},github),{agrees:true,npmVersion:'0.4.1',githubVersion:'0.4.1'});
  assert.equal(releaseState({version:'0.4.2'},github).agrees,false);
  assert.throws(()=>releaseState({version:'0.4.1'},{...github,draft:true}));
  assert.throws(()=>releaseState({version:'0.4.1'},{...github,prerelease:true}));
  assert.throws(()=>releaseState({version:'0.4.1'},{tag_name:'v0.4.1'}));
  for (const value of ['0.4.2-rc.1','<img src=x>','https://example.com','1.2.3.4','',null]) {
    assert.equal(versionParts(value),null);
    assert.throws(()=>releaseState({version:value},github));
  }
  assert.equal(compareVersions('0.4.10','0.4.2'),1);
  assert.equal(compareVersions('v1.0.0','0.99.99'),1);
  assert.equal(compareVersions('0.4.1','v0.4.1'),0);
});

test('release snapshot separates published versions and the review candidate', async () => {
  const changelog = await readFile(join(dist,'changelog/index.html'),'utf8');
  assert.match(changelog,/data-candidate-entry/);
  assert.match(changelog,/Unreleased candidate/);
  assert.match(changelog,/Not yet available through the public latest install commands/);
  const snapshot = JSON.parse(await readFile(join(dist,'assets/release.json'),'utf8'));
  assert.equal(snapshot.stable,'0.4.1');
  assert.equal(snapshot.candidate,'0.4.2');
  assert.match(changelog,/Release snapshot · v0\.4\.1/);
});

test('static package has no inline executables, install scripts, trackers or external assets', async () => {
  for (const file of htmlFiles) {
    const html = await readFile(file,'utf8');
    assert.doesNotMatch(html,/<script(?![^>]*src=)[^>]*>/i);
    assert.doesNotMatch(html,/\son\w+="/i);
    assert.doesNotMatch(html,/(?:src|rel="stylesheet" href)="https?:/i);
  }
  const pkg = JSON.parse(await readFile(join(root,'package.json'),'utf8'));
  assert.equal(pkg.dependencies,undefined);
  assert.equal(pkg.scripts.postinstall,undefined);
  const headers = await readFile(join(dist,'_headers'),'utf8');
  assert.match(headers,/script-src 'self'/);
  assert.match(headers,/frame-ancestors 'none'/);
  assert.doesNotMatch(headers,/unsafe-inline|unsafe-eval/);
});
