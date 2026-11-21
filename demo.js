import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';
import { startCaServer } from './src/ca.js';
import { MeshNode } from './src/mesh-node.js';
import { createRootCa, createCsr, generateRsaKeys, issueCertificate, ROOT_CA_NAME } from './src/pki.js';
import { CA_PORT, CA_URL, LINKS, PORTS, RADIO, neighborsOf } from './src/config.js';

const t0 = Date.now();
const log = (line) => console.log(`${String(Date.now() - t0).padStart(6)} ms  ${line}`);
const section = (title) => console.log(`\n========== ${title} ==========`);

async function waitFor(predicate, what, timeoutMs = 15_000) {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await sleep(20);
  }
}

const ids = Object.keys(PORTS);

section('0. Certificate authority and node start-up');
log(`topology: ${ids.length} nodes, links ${LINKS.map((l) => l.join('–')).join(', ')}`);
log(`radio: MTU ${RADIO.mtu} B per frame, ${RADIO.bitrate} bit/s`);
const ca = await startCaServer({ port: CA_PORT, allowedIds: ids, log: (m) => log(`[CA] ${m}`) });

const nodes = {};
for (const id of ids) {
  nodes[id] = new MeshNode(id, { port: PORTS[id], neighbors: neighborsOf(id), ports: PORTS, caUrl: CA_URL, radio: RADIO, log });
  await nodes[id].start();
}
for (const node of Object.values(nodes)) node.connectNeighbors();
await waitFor(() => Object.values(nodes).every((n) => n.routes.size === ids.length - 1), 'routing convergence');
log('link-state routing converged on every node');
for (const id of ['A', 'G']) {
  console.log(`routing table of ${id}:`);
  for (const [dst, r] of nodes[id].routes) console.log(`   to ${dst}: next hop ${r.next}, ${r.hops} hop(s), path ${r.path.join('→')}`);
}

section('1. Handshake between neighbours A and B (1 hop)');
await nodes.A.handshake('B');
await nodes.A.sendChat('B', 'Привіт, B! Це A.');
await once(nodes.B, 'chat');
await nodes.B.sendChat('A', 'Привіт, A! Канал захищений.');
await once(nodes.A, 'chat');

section('2. Handshake between A and G through intermediate nodes (4 hops)');
await nodes.A.handshake('G');
await nodes.A.sendChat('G', 'G, чуєш мене? Пакети йдуть через B, D і F.');
await once(nodes.G, 'chat');
await nodes.G.sendChat('A', 'Чую, A. Проміжні вузли бачать лише шифротекст.');
await once(nodes.A, 'chat');

const file = await readFile(new URL('./demo/message.txt', import.meta.url));
const fileStart = Date.now();
await nodes.A.sendFile('G', 'message.txt', file);
const [received] = await once(nodes.G, 'file');
log(`file delivered in ${Date.now() - fileStart} ms, ${received.data.length} B, integrity ${received.ok ? 'OK' : 'FAILED'}, identical: ${received.data.equals(file)}`);

section('3. Broadcast from A along the shortest-path tree');
const tree = nodes.A.shortestPathTree('A');
log(`tree rooted at A: ${[...tree].filter(([, p]) => p).map(([n, p]) => `${p}→${n}`).join(', ')}`);
const deliveries = Promise.all(ids.filter((id) => id !== 'A').map((id) => once(nodes[id], 'broadcast')));
await nodes.A.broadcast('Усім вузлам: планове оновлення ключів о 12:00.');
await deliveries;
const edges = LINKS.length;
log(`all ${ids.length - 1} nodes received the broadcast once; link transmissions: tree ${ids.length - 1}, naive flooding would need ${2 * edges - (ids.length - 1)}`);

section('4a. Attack: compromised router C replaces E\'s certificate with one from a rogue CA');
const rogueCa = createRootCa(ROOT_CA_NAME);
const fakeForE = issueCertificate(rogueCa, createCsr('E', generateRsaKeys()));
log(`attacker built a rogue CA named "${ROOT_CA_NAME}" and a certificate CN=E serial=${fakeForE.serial}`);
nodes.C.forwardHook = (packet) => {
  if (packet.body.type === 'server_hello' && packet.src === 'E') {
    packet.body.certificate = fakeForE.pem;
    log('[C] (attacker) swapped the certificate inside ServerHello');
  }
};
let peerAbort = once(nodes.E, 'tls-error');
await nodes.A.handshake('E').catch((err) => log(`result: A refused to continue — ${err.message}`));
await peerAbort;

section('4b. Attack: router C presents its own valid certificate instead of E\'s');
nodes.C.forwardHook = (packet) => {
  if (packet.body.type === 'server_hello' && packet.src === 'E') {
    packet.body.certificate = nodes.C.certPem;
    log('[C] (attacker) put its own CA-signed certificate into ServerHello');
  }
};
peerAbort = once(nodes.E, 'tls-error');
await nodes.A.handshake('E').catch((err) => log(`result: A refused to continue — ${err.message}`));
await peerAbort;
nodes.C.forwardHook = null;

section('4c. Attack: router C flips one byte of an encrypted record');
await nodes.A.handshake('E');
nodes.C.forwardHook = (packet) => {
  if (packet.body.type === 'app' && packet.src === 'A') {
    const ct = Buffer.from(packet.body.ct, 'base64');
    ct[5] ^= 0x01;
    packet.body.ct = ct.toString('base64');
    log('[C] (attacker) modified ciphertext of an application record');
  }
};
const tlsError = once(nodes.E, 'tls-error');
await nodes.A.sendChat('E', 'Переказати 100 грн на рахунок 1');
await tlsError;
await waitFor(() => !nodes.A.establishedSession('E'), 'A to drop the broken session');
nodes.C.forwardHook = null;
log('router C is honest again; A sends the message once more (new handshake is made automatically)');
await nodes.A.sendChat('E', 'Переказати 100 грн на рахунок 1');
await once(nodes.E, 'chat');

section('5. Link D–F goes down: routes are recomputed, the A–G session survives');
const routeChanged = once(nodes.A, 'routes');
nodes.D.dropLink('F');
await routeChanged;
await waitFor(() => nodes.A.routes.get('G').path.join('') === 'ACEFG' && nodes.G.routes.get('A').next === 'F' && nodes.F.routes.get('A').next === 'E', 'new routes');
log(`new path A→G: ${nodes.A.routes.get('G').path.join('→')}`);
await nodes.A.sendChat('G', 'Я на зв\'язку новим маршрутом, ключі сеансу ті самі.');
await once(nodes.G, 'chat');

section('6. Certificate of G is revoked by the CA');
await fetch(`${CA_URL}/revoke`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ serial: nodes.G.certSerial }) });
await nodes.B.handshake('G').catch((err) => log(`result: B refused to continue — ${err.message}`));
log(`already established session A–G is still open: ${Boolean(nodes.A.establishedSession('G'))} (a revocation affects new handshakes)`);

section('7. Radio link statistics');
const rows = [];
for (const node of Object.values(nodes)) {
  for (const s of node.linkStats()) if (node.id < s.peer) rows.push({ link: `${node.id}–${s.peer}`, 'frames →': s.framesOut, 'bytes →': s.bytesOut, 'frames ←': s.framesIn, 'bytes ←': s.bytesIn });
}
console.table(rows);
const totalBytes = rows.reduce((sum, r) => sum + r['bytes →'] + r['bytes ←'], 0);
log(`total on air (links still up): ${rows.reduce((s, r) => s + r['frames →'] + r['frames ←'], 0)} frames, ${totalBytes} B, ${((totalBytes * 8) / RADIO.bitrate).toFixed(2)} s of airtime`);

for (const node of Object.values(nodes)) await node.stop();
await ca.close();
log('done');
