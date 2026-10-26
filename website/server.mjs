import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), 'dist');
const mime = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json','.svg':'image/svg+xml','.xml':'application/xml; charset=utf-8','.txt':'text/plain; charset=utf-8'};
const csp = "default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.github.com https://registry.npmjs.org https://cloudflareinsights.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
const server = http.createServer(async (req,res) => {
  res.setHeader('Content-Security-Policy',csp);
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Cache-Control','no-store');
  if (!['GET','HEAD'].includes(req.method)) { res.writeHead(405,{'Allow':'GET, HEAD'}); res.end(); return; }
  let target;
  try {
    const path = decodeURIComponent(new URL(req.url,'http://localhost').pathname);
    if (path.includes('\0') || path.includes('\\')) throw new Error('Invalid path');
    target = resolve(root, '.' + path);
    if (target !== root && !target.startsWith(root + sep)) throw new Error('Invalid path');
    const info = await stat(target);
    if (info.isDirectory()) {
      if (!path.endsWith('/')) { res.writeHead(308,{Location:path+'/'}); res.end(); return; }
      target = resolve(target,'index.html');
    }
    const contents = await readFile(target);
    res.writeHead(200,{'Content-Type':mime[extname(target)] || 'application/octet-stream'});
    res.end(req.method === 'HEAD' ? undefined : contents);
  } catch {
    res.writeHead(404,{'Content-Type':'text/html; charset=utf-8'});
    res.end(req.method === 'HEAD' ? undefined : await readFile(resolve(root,'404.html')));
  }
});
const port = Number(process.env.PORT || 4173);
server.listen(port,'127.0.0.1',()=>console.log(`MCPSense website: http://127.0.0.1:${port}`));
