const {test} = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const {createHost,filesystem} = require('./node.cjs');
const invoke = (host, method, ...args) => new Promise((resolve, reject) => host[method](...args, (error, value) => error ? reject(Error(error)) : resolve(value)));

test('directory-only filesystem opens reject ordinary files on Windows and Unix',async()=>{
  const fs=require('fs'),path=require('path'),os=require('os');
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-directory-'));
  const file=path.join(directory,'ordinary.txt');fs.writeFileSync(file,'control');
  const api=filesystem();
  const open=value=>new Promise((resolve,reject)=>api.open(value,api.constants.O_DIRECTORY,0,(error,fd)=>error?reject(error):resolve(fd)));
  const fd=await open(directory);assert.ok(fs.fstatSync(fd).isDirectory());fs.closeSync(fd);
  await assert.rejects(open(file),error=>error.code==='ENOTDIR');
});

async function withPeer(handler, run) {
  const host = createHost();
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {await run(host, server.address().port);} finally {await host.closeAll(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve));}
}

test('pinned lookup, literal body, short reads and EOF preserve every byte', async () => {
  const expected = 'x'.repeat(2031);
  await withPeer((req, res) => {
    assert.equal(req.headers.host.split(':')[0], 'fixture.invalid');
    let input = ''; req.on('data', bytes => input += bytes); req.on('end', () => {assert.equal(input, 'literal; & $()'); res.end(expected);});
  }, async (host, port) => {
    const r = await invoke(host, 'request', 'http://fixture.invalid:' + port + '/', 'POST', '{}', Buffer.from('literal; & $()'), '["127.0.0.1"]');
    assert.equal(r.status, 200);
    const chunks = [];
    for (;;) {const bytes = await invoke(host, 'read', r.id, 512); assert.ok(bytes.length <= 512); if (!bytes.length) break; chunks.push(bytes);}
    assert.equal(Buffer.concat(chunks).toString(), expected); host.closeStream(r.id);
  });
});

test('streamed data is available before EOF and cancelling a read settles once', async () => {
  await withPeer((_req, res) => {res.writeHead(200, {'Content-Type':'text/event-stream'}); res.write('data: {}\n\n');}, async (host, port) => {
    const r = await invoke(host, 'request', 'http://127.0.0.1:' + port, 'GET', '{}', new Uint8Array(), '["127.0.0.1"]');
    assert.equal(Buffer.from(await invoke(host, 'read', r.id, 64)).toString(), 'data: {}\n\n');
    let calls = 0;
    const abort = host.read(r.id, 64, error => {calls++; assert.ok(error);});
    abort(); abort(); await new Promise(resolve => setImmediate(resolve)); assert.equal(calls, 1);
  });
});

test('HTTP core does not follow redirects or use environment proxies', async () => {
  const prior = process.env.HTTP_PROXY; process.env.HTTP_PROXY = 'http://127.0.0.1:1';
  try {
    let calls = 0;
    await withPeer((_req, res) => {calls++; res.writeHead(302, {Location:'http://other.invalid/'}); res.end();}, async (host, port) => {
      const r = await invoke(host, 'request', 'http://127.0.0.1:' + port, 'GET', '{}', new Uint8Array(), '["127.0.0.1"]');
      assert.equal(r.status, 302); assert.equal(calls, 1); host.closeStream(r.id);
    });
  } finally {if (prior === undefined) delete process.env.HTTP_PROXY; else process.env.HTTP_PROXY = prior;}
});

test('invalid request capability inputs fail before connection', async () => {
  const host = createHost();
  try {
    for (const [url, ips] of [['file:///private','["127.0.0.1"]'], ['http://user:secret@fixture.invalid','["127.0.0.1"]'], ['https://fixture.invalid','["not-an-ip"]']]) {
      await assert.rejects(invoke(host, 'request', url, 'GET', '{}', new Uint8Array(), ips));
    }
  } finally {await host.closeAll();}
});

test('authorized process argv stays literal and output is streamed', async () => {
  const host = createHost(), args = ['value; & $()', 'space value', '--label=literal'];
  try {
    const child = await invoke(host, 'startProcess', [process.execPath, '-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', ...args]);
    const chunks = [];
    for (;;) {const bytes = await invoke(host, 'read', child.stream, 512); if (!bytes.length) break; chunks.push(bytes);}
    assert.deepEqual(JSON.parse(Buffer.concat(chunks).toString()), args);
    host.closeStream(child.stream); host.closeProcess(child.id);
    await assert.rejects(invoke(host, 'startProcess', ['definitely-not-a-real-executable-23']));
  } finally {await host.closeAll();}
});
