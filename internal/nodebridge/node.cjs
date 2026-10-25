'use strict';
// Trusted host adapters only. Detection, limits, protocol parsing, reporting and
// permission decisions stay in the same Go engine used by native installations.
const fs = require('fs');
const path = require('path');
const dns = require('dns');
const net = require('net');
const http = require('http');
const https = require('https');
const {spawn} = require('child_process');

function filesystem() {
  if (process.platform !== 'win32' || fs.constants.O_DIRECTORY !== undefined) return fs;
  // Go 1.27 requests O_DIRECTORY for directory walks. Node on Windows omits
  // that flag. Emulate its type check against the opened descriptor, without
  // weakening it into a regular-file open or racing a path-based stat.
  const directoryFlag = 0x10000000;
  return {...fs, constants:{...fs.constants,O_DIRECTORY:directoryFlag},
    open(file, flags, mode, callback) {
      if (!(flags & directoryFlag)) return fs.open(file,flags,mode,callback);
      fs.open(file,flags & ~directoryFlag,mode,(error,fd)=>{
        if (error) return callback(error);
        fs.fstat(fd,(error,stat)=>{
          if (!error && stat.isDirectory()) return callback(null,fd);
          fs.close(fd,()=>callback(error || Object.assign(Error('not a directory'),{code:'ENOTDIR'})));
        });
      });
    }
  };
}

function createHost() {
  let next = 1, signalHandler;
  const streams = new Map(), processes = new Map(), requests = new Set(), cleanup = new Set();
  const settle = callback => {
    let done = false;
    return (error, value) => {if (done) return false; done = true; callback(error ? 'operation failed' : null, value); return true;};
  };
  function stream(readable, close) {
    const id = next++;
    const state = {readable, close, error: false, ended: false, pending: null};
    readable.pause();
    readable.on('error', () => {state.error = true; if (state.pending) state.pending();});
    readable.on('end', () => {state.ended = true; if (state.pending) state.pending();});
    readable.on('close', () => {if (!readable.readableEnded) state.error = true; if (state.pending) state.pending();});
    streams.set(id, state); return id;
  }
  function closeStream(id) {
    const state = streams.get(id); if (!state) return;
    streams.delete(id); state.error = true;
    if (state.pending) state.pending();
    state.readable.destroy(); if (state.close) state.close();
  }
  function closeProcess(id) {
    const child = processes.get(id); if (!child) return;
    processes.delete(id); child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
    if (process.platform === 'win32') {
      const promise = new Promise(resolve => {
        const killer = spawn(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], {shell:false, windowsHide:true, stdio:'ignore'});
        const timer = setTimeout(() => {killer.kill(); child.kill(); resolve();}, 2000);
        killer.once('error', () => {clearTimeout(timer); child.kill(); resolve();});
        killer.once('close', () => {clearTimeout(timer); child.kill(); resolve();});
      });
      cleanup.add(promise); promise.finally(() => cleanup.delete(promise));
    } else {
      try {process.kill(-child.pid, 'SIGKILL');} catch {child.kill();}
    }
  }
  function onSignal() {if (signalHandler) signalHandler();}
  const host = {
    sourceHash: require('crypto').createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),
    platform: process.platform,
    absolute: value => path.resolve(value), dirname: value => path.dirname(value), basename: value => path.basename(value),
    mkdir(value, mode, callback) {const done = settle(callback); fs.mkdir(value, {recursive:true, mode}, error => done(error, true)); return () => done(true, null);},
    setSignalHandler(handler) {signalHandler = handler; process.on('SIGINT', onSignal); process.on('SIGTERM', onSignal);},
    clearSignalHandler() {signalHandler = null; process.removeListener('SIGINT', onSignal); process.removeListener('SIGTERM', onSignal);},
    lookup(name, callback) {
      const done = settle(callback);
      dns.lookup(name, {all:true, verbatim:true}, (error, values) => {
        if (error || !values.length || values.length > 64) return done(true, null);
        done(null, JSON.stringify(values.map(value => value.address)));
      });
      return () => done(true, null);
    },
    request(address, method, headerJSON, bytes, ipJSON, callback) {
      const done = settle(callback); let req, agent;
      try {
        const url = new URL(address), ips = JSON.parse(ipJSON), headers = JSON.parse(headerJSON);
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !ips.length || ips.length > 64 || ips.some(ip => !net.isIP(ip)) || bytes.length > (4 << 20)) throw Error('invalid request');
        const module = url.protocol === 'https:' ? https : http;
        // A private Agent avoids global/environment proxy configuration. Node's
        // HTTP core does not follow redirects; the Go client decides that.
        agent = new module.Agent({keepAlive:false, proxyEnv:{}});
        const lookup = (_name, options, cb) => {
          const matches = ips.filter(ip => !options.family || net.isIP(ip) === options.family);
          if (!matches.length) return cb(Error('no permitted address'));
          if (options.all) cb(null, matches.map(address => ({address, family:net.isIP(address)})));
          else cb(null, matches[0], net.isIP(matches[0]));
        };
        req = module.request(url, {method, headers, agent, lookup, maxHeaderSize:64<<10}, response => {
          const id = stream(response, () => {req.destroy(); agent.destroy(); requests.delete(req);});
          done(null, {id, status:response.statusCode, headers:JSON.stringify(response.rawHeaders)});
        });
        requests.add(req);
        req.once('error', () => {requests.delete(req); agent.destroy(); done(true, null);});
        req.end(Buffer.from(bytes));
      } catch {if (agent) agent.destroy(); done(true, null);}
      return () => {if (req) {requests.delete(req); req.destroy();} if (agent) agent.destroy(); done(true, null);};
    },
    read(id, size, callback) {
      const done = settle(callback), state = streams.get(id);
      if (!state || state.pending || !Number.isInteger(size) || size < 1 || size > (64 << 10)) {done(true, null); return () => {};}
      let stopped = false;
      function finish(error, value) {
        if (stopped) return; stopped = true;
        state.pending = null; state.readable.removeListener('readable', check); done(error, value);
      }
      function check() {
        if (state.error) return finish(true, null);
        const count = Math.min(size, state.readable.readableLength);
        if (count) {const bytes = state.readable.read(count); if (bytes) return finish(null, bytes);}
        // Reading exactly the last buffered bytes can defer Node's end event
        // until another read is attempted. Drive that transition without
        // consuming bytes that belong to a later bounded Go read.
        if (!count) state.readable.read(0);
        if (state.ended || state.readable.readableEnded) finish(null, new Uint8Array());
      }
      state.pending = check; state.readable.on('readable', check); check();
      return () => {finish(true, null); closeStream(id);};
    },
    closeStream,
    startProcess(parts, callback) {
      const done = settle(callback); let child, id;
      try {
        if (!Array.isArray(parts) || !parts.length || parts.length > 1024 || parts.some(p => typeof p !== 'string' || p.includes('\0'))) throw Error('invalid argv');
        child = spawn(parts[0], parts.slice(1), {shell:false, windowsHide:true, detached:process.platform!=='win32', stdio:['pipe','pipe','pipe']});
        id = next++; processes.set(id, child);
        const output = stream(child.stdout);
        child.stderr.on('data', () => {}); // drain without retaining or exporting server logs
        child.stdin.on('error', () => {});
        child.once('error', () => {closeStream(output); processes.delete(id); done(true, null);});
        child.once('spawn', () => done(null, {id, stream:output}));
      } catch {done(true, null);}
      return () => {if (id) closeProcess(id); done(true, null);};
    },
    write(id, bytes, callback) {
      const done = settle(callback), child = processes.get(id);
      if (!child || bytes.length > (4 << 20)) {done(true, null); return () => {};}
      child.stdin.write(Buffer.from(bytes), error => done(error, true));
      return () => {closeProcess(id); done(true, null);};
    },
    closeInput(id) {const child = processes.get(id); if (child) child.stdin.end();},
    closeProcess,
    async closeAll() {
      host.clearSignalHandler();
      for (const id of [...streams.keys()]) closeStream(id);
      for (const id of [...processes.keys()]) closeProcess(id);
      for (const req of requests) req.destroy(); requests.clear();
      await Promise.allSettled([...cleanup]);
    }
  };
  return host;
}
module.exports = {createHost,filesystem};
