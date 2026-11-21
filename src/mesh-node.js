import net from 'node:net';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { RadioLink } from './link.js';
import { generateRsaKeys, createCsr, verifyCertificate } from './pki.js';
import { TlsSession, short } from './tls.js';

const HANDSHAKE_TIMEOUT_MS = 30_000;
const MAX_TTL = 16;

/**
 * One node of the mesh. Layers, bottom to top:
 *   radio link (frames <= MTU, airtime delay)  ->  network (link-state routing, forwarding)
 *   ->  end-to-end TLS sessions  ->  application (chat, file, broadcast).
 * Intermediate nodes only forward TLS packets; they never see session keys.
 */
export class MeshNode extends EventEmitter {
  constructor(id, { port, neighbors, ports, caUrl, radio, log = console.log }) {
    super();
    this.id = id;
    this.port = port;
    this.neighbors = neighbors;
    this.ports = ports;
    this.caUrl = caUrl;
    this.radio = radio;
    this.logger = log;
    this.links = new Map(); // neighbor id -> RadioLink
    this.lsdb = new Map(); // origin -> { seq, neighbors }
    this.lsaSeq = 0;
    this.routes = new Map(); // destination -> { next, hops, path }
    this.sessions = new Map(); // sid -> TlsSession
    this.pending = new Map(); // peer -> Promise<TlsSession> of a running client handshake
    this.seenBroadcasts = new Set();
    this.forwardHook = null; // lets the demo turn this node into a compromised router
  }

  log(msg) {
    this.logger(`[${this.id}] ${msg}`);
  }

  async #ca(method, path, body) {
    const res = await fetch(this.caUrl + path, {
      method,
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await res.json();
    if (!res.ok) throw new Error(`CA ${path}: ${json.error}`);
    return json;
  }

  // ---------- bootstrap ----------

  async start() {
    const keys = generateRsaKeys();
    this.privateKey = keys.privateKey;
    this.rootPem = (await this.#ca('GET', '/root')).pem;
    const issued = await this.#ca('POST', '/issue', { csr: createCsr(this.id, keys) });
    this.certPem = issued.cert;
    this.certSerial = issued.serial;
    this.server = net.createServer((socket) => this.#attach(socket));
    await new Promise((resolve) => this.server.listen(this.port, '127.0.0.1', resolve));
    this.#originateLsa();
    this.log(`up on :${this.port}, RSA-2048 key generated, certificate CN=${this.id} serial=${this.certSerial} issued by CA`);
  }

  /** The node with the smaller id dials, the other one accepts. */
  connectNeighbors() {
    for (const peer of this.neighbors) if (peer > this.id) this.#dial(peer, 0);
  }

  #dial(peer, attempt) {
    const socket = net.connect(this.ports[peer], '127.0.0.1');
    let connected = false;
    socket.once('connect', () => {
      connected = true;
      this.#attach(socket);
    });
    socket.once('error', () => {
      if (!connected && attempt < 40) setTimeout(() => this.#dial(peer, attempt + 1), 250);
    });
  }

  #attach(socket) {
    const link = new RadioLink(socket, this.radio);
    link.on('message', (buf) => this.#onPacket(JSON.parse(buf), link));
    link.on('close', () => {
      if (!this.stopping && link.peer && this.links.get(link.peer) === link) {
        this.links.delete(link.peer);
        this.log(`link ${this.id}–${link.peer} is DOWN`);
        this.#originateLsa();
      }
    });
    link.send(Buffer.from(JSON.stringify({ proto: 'HELLO', src: this.id, body: { id: this.id } })));
  }

  dropLink(peer) {
    this.links.get(peer)?.close();
  }

  async stop() {
    this.stopping = true;
    for (const link of this.links.values()) link.close();
    await new Promise((resolve) => this.server.close(resolve));
  }

  // ---------- network layer: link-state routing ----------

  #sendOnLink(peer, packet) {
    const link = this.links.get(peer);
    if (!link) return false;
    link.send(Buffer.from(JSON.stringify(packet)));
    return true;
  }

  #originateLsa() {
    const lsa = { origin: this.id, seq: ++this.lsaSeq, neighbors: [...this.links.keys()].sort() };
    this.lsdb.set(this.id, lsa);
    this.#recomputeRoutes();
    for (const peer of this.links.keys()) this.#sendOnLink(peer, { proto: 'LSA', src: this.id, body: lsa });
  }

  #onLsa(lsa, fromPeer) {
    const known = this.lsdb.get(lsa.origin);
    if (known && known.seq >= lsa.seq) return;
    this.lsdb.set(lsa.origin, lsa);
    this.#recomputeRoutes();
    // flooding: pass the advertisement to every neighbor except the one it came from
    for (const peer of this.links.keys()) if (peer !== fromPeer) this.#sendOnLink(peer, { proto: 'LSA', src: this.id, body: lsa });
  }

  /** Topology graph from the link-state database; an edge counts only if both ends advertise it. */
  graph() {
    const g = new Map();
    for (const [origin, lsa] of this.lsdb) {
      g.set(origin, lsa.neighbors.filter((n) => this.lsdb.get(n)?.neighbors.includes(origin)).sort());
    }
    return g;
  }

  /** Breadth-first shortest-path tree (all links cost 1, ties broken by node id so every node builds the same tree). */
  shortestPathTree(root) {
    const g = this.graph();
    const parent = new Map([[root, null]]);
    const queue = [root];
    while (queue.length) {
      const node = queue.shift();
      for (const next of g.get(node) ?? []) {
        if (!parent.has(next)) {
          parent.set(next, node);
          queue.push(next);
        }
      }
    }
    return parent;
  }

  #recomputeRoutes() {
    const parent = this.shortestPathTree(this.id);
    const before = JSON.stringify([...this.routes]);
    this.routes.clear();
    for (const dst of parent.keys()) {
      if (dst === this.id) continue;
      const path = [dst];
      while (parent.get(path[0]) !== null) path.unshift(parent.get(path[0]));
      this.routes.set(dst, { next: path[1], hops: path.length - 1, path });
    }
    if (before !== JSON.stringify([...this.routes])) this.emit('routes');
  }

  send(dst, proto, body) {
    return this.#route({ proto, src: this.id, dst, ttl: MAX_TTL, body });
  }

  #route(packet) {
    const next = this.links.has(packet.dst) ? packet.dst : this.routes.get(packet.dst)?.next;
    if (!next || !this.#sendOnLink(next, packet)) {
      this.log(`no route to ${packet.dst}, packet dropped`);
      return false;
    }
    return true;
  }

  #onPacket(packet, link) {
    if (packet.proto === 'HELLO') {
      link.peer = packet.body.id;
      this.links.set(link.peer, link);
      this.log(`link ${this.id}–${link.peer} is UP`);
      for (const lsa of this.lsdb.values()) this.#sendOnLink(link.peer, { proto: 'LSA', src: this.id, body: lsa });
      this.#originateLsa();
      return;
    }
    if (packet.proto === 'LSA') return this.#onLsa(packet.body, link.peer);
    if (packet.dst === this.id) return this.#onTls(packet).catch((err) => this.log(`error: ${err.message}`));

    if (--packet.ttl <= 0) {
      this.log(`TTL expired for packet ${packet.src}→${packet.dst}, dropped`);
      return;
    }
    this.forwardHook?.(packet);
    const via = this.links.has(packet.dst) ? packet.dst : this.routes.get(packet.dst)?.next;
    this.log(`forward ${packet.body.type} ${packet.src}→${packet.dst} to ${via} (opaque to this node)`);
    this.#route(packet);
  }

  // ---------- end-to-end TLS ----------

  establishedSession(peer) {
    let found = null;
    for (const s of this.sessions.values()) if (s.peer === peer && s.established && (!found || s.startedAt > found.startedAt)) found = s;
    return found;
  }

  /** Client side of the handshake (steps 1-7). Resolves with an established session. */
  handshake(peer) {
    const existing = this.establishedSession(peer);
    if (existing) return Promise.resolve(existing);
    if (this.pending.has(peer)) return this.pending.get(peer);

    const session = new TlsSession({ role: 'client', self: this.id, peer });
    this.sessions.set(session.sid, session);
    const route = this.routes.get(peer);
    const promise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`handshake with ${peer} timed out`)), HANDSHAKE_TIMEOUT_MS);
      session.done = (err) => {
        clearTimeout(timer);
        this.pending.delete(peer);
        if (err) {
          this.sessions.delete(session.sid);
          reject(err);
        } else resolve(session);
      };
    });
    this.pending.set(peer, promise);
    const hello = session.clientHello();
    this.log(`(1) ClientHello → ${peer} [sid=${session.sid}] client_random=${short(session.clientRandom)} route ${route?.path.join('→')} (${route?.hops} hop(s))`);
    this.send(peer, 'TLS', hello);
    return promise;
  }

  async verifyPeerCertificate(pem, expectedId, { online = true } = {}) {
    const local = verifyCertificate(pem, this.rootPem, expectedId);
    if (!local.ok) return local;
    if (online) {
      const answer = await this.#ca('POST', '/verify', { cert: pem });
      if (!answer.valid) return { ok: false, reason: `CA rejected the certificate: ${answer.reason}` };
    }
    return local;
  }

  #fail(session, peer, reason, notifyPeer = true) {
    this.log(`✗ handshake/session with ${peer} aborted: ${reason}`);
    if (notifyPeer) this.send(peer, 'TLS', { type: 'alert', sid: session.sid, reason });
    this.sessions.delete(session.sid);
    session.done?.(new Error(reason));
    this.emit('tls-error', { peer, reason });
  }

  async #onTls(packet) {
    const msg = packet.body;
    const peer = packet.src;
    let session = this.sessions.get(msg.sid);

    if (msg.type === 'client_hello') {
      session = new TlsSession({ role: 'server', self: this.id, peer, sid: msg.sid });
      this.sessions.set(session.sid, session);
      session.receiveClientHello(msg);
      const reply = session.serverHello(this.certPem);
      this.log(`(2) ServerHello → ${peer} [sid=${session.sid}] server_random=${short(session.serverRandom)} + X.509 certificate CN=${this.id} serial=${this.certSerial}`);
      this.send(peer, 'TLS', reply);
      return;
    }
    if (!session) return;

    try {
      switch (msg.type) {
        case 'server_hello': {
          session.receiveServerHello(msg);
          const check = await this.verifyPeerCertificate(msg.certificate, peer);
          if (!check.ok) return this.#fail(session, peer, `certificate check failed: ${check.reason}`);
          this.log(`(3) certificate of ${peer} verified: signed by root CA, CN=${check.cn}, not expired; CA /verify: not revoked`);
          const kx = session.clientKeyExchange(check.cert.publicKey);
          this.log(`(4) premaster secret (${kx.premasterLength} B, sha256=${session.premasterFingerprint}) encrypted with ${peer}'s RSA public key (RSA-OAEP, ${kx.encryptedLength} B) → ${peer}`);
          this.send(peer, 'TLS', kx.body);
          this.#logKeys(session);
          const fin = session.finished();
          this.log(`(6) Finished "ready" → ${peer}, encrypted with client_write_key, verify_data=${fin.verifyData}`);
          this.send(peer, 'TLS', fin.body);
          return;
        }
        case 'client_key_exchange': {
          const kx = session.receiveClientKeyExchange(msg, this.privateKey);
          this.log(`(4) premaster secret decrypted with own private key (${kx.premasterLength} B, sha256=${session.premasterFingerprint})`);
          this.#logKeys(session);
          return;
        }
        case 'finished': {
          const { verifyData } = session.receiveFinished(msg);
          this.log(`(6) Finished "ready" from ${peer} decrypted, verify_data=${verifyData} matches`);
          if (session.role === 'server') {
            const fin = session.finished();
            this.log(`(6) Finished "ready" → ${peer}, encrypted with server_write_key, verify_data=${fin.verifyData}`);
            this.send(peer, 'TLS', fin.body);
          }
          this.log(`(7) handshake with ${peer} complete in ${Date.now() - session.startedAt} ms, secure channel sid=${session.sid} (AES-128-GCM)`);
          this.emit('session', session);
          session.done?.();
          return;
        }
        case 'app':
          return this.#onAppData(session, JSON.parse(session.open(msg, 'app')));
        case 'alert':
          return this.#fail(session, peer, `peer sent alert: ${msg.reason}`, false);
      }
    } catch (err) {
      this.#fail(session, peer, err.message);
    }
  }

  #logKeys(session) {
    const k = session.keys;
    this.log(
      `(5) session keys derived: master=${short(session.master)} client_write_key=${short(k.clientWriteKey)} server_write_key=${short(k.serverWriteKey)}`,
    );
  }

  // ---------- application layer ----------

  #sendApp(session, payload) {
    const plaintext = Buffer.from(JSON.stringify(payload));
    const record = session.seal('app', plaintext);
    this.send(session.peer, 'TLS', { type: 'app', sid: session.sid, ...record });
    return { plaintextBytes: plaintext.length, seq: record.seq };
  }

  async sendChat(peer, text) {
    const session = await this.handshake(peer);
    const info = this.#sendApp(session, { kind: 'chat', text });
    this.log(`chat → ${peer}: "${text}" (record seq=${info.seq}, ${info.plaintextBytes} B encrypted)`);
  }

  async sendFile(peer, name, data) {
    const session = await this.handshake(peer);
    const sha256 = crypto.createHash('sha256').update(data).digest('hex');
    const info = this.#sendApp(session, { kind: 'file', name, size: data.length, sha256, data: data.toString('base64') });
    this.log(`file → ${peer}: ${name} (${data.length} B, sha256=${sha256.slice(0, 16)}…, record seq=${info.seq})`);
  }

  #onAppData(session, payload) {
    const from = session.peer;
    if (payload.kind === 'chat') {
      this.log(`chat ← ${from}: "${payload.text}" (decrypted with session ${session.sid})`);
      this.emit('chat', { from, text: payload.text });
    } else if (payload.kind === 'file') {
      const data = Buffer.from(payload.data, 'base64');
      const ok = crypto.createHash('sha256').update(data).digest('hex') === payload.sha256;
      this.log(`file ← ${from}: ${payload.name} (${data.length} B), sha256 ${ok ? 'matches' : 'MISMATCH'}`);
      this.emit('file', { from, name: payload.name, data, ok });
    } else if (payload.kind === 'broadcast') {
      this.#onBroadcast(payload, from);
    }
  }

  /**
   * Broadcast along the shortest-path tree rooted at the origin: every node forwards only to its
   * children, so each of the N-1 receivers gets the message exactly once. Each hop is protected by the
   * TLS session of that link; the origin's signature lets every receiver check who wrote the message.
   */
  async broadcast(text) {
    const payload = { origin: this.id, bid: crypto.randomBytes(4).toString('hex'), text, ts: Date.now() };
    const signature = crypto.sign('sha256', Buffer.from(JSON.stringify(payload)), this.privateKey).toString('base64');
    this.seenBroadcasts.add(`${payload.origin}:${payload.bid}`);
    this.log(`broadcast ${payload.bid} "${text}" signed with own private key`);
    await this.#relayBroadcast({ kind: 'broadcast', payload, signature, certificate: this.certPem });
  }

  treeChildren(root) {
    return [...this.shortestPathTree(root)].filter(([, parent]) => parent === this.id).map(([node]) => node).sort();
  }

  async #relayBroadcast(message) {
    const children = this.treeChildren(message.payload.origin);
    if (!children.length) return;
    this.log(`broadcast ${message.payload.bid}: forwarding to tree children [${children.join(', ')}]`);
    await Promise.all(
      children.map(async (child) => {
        const session = await this.handshake(child);
        this.#sendApp(session, message);
      }),
    );
  }

  #onBroadcast(message, fromPeer) {
    const { payload } = message;
    const key = `${payload.origin}:${payload.bid}`;
    if (this.seenBroadcasts.has(key)) {
      this.log(`broadcast ${payload.bid} already seen, ignored`);
      return;
    }
    this.seenBroadcasts.add(key);
    const check = verifyCertificate(message.certificate, this.rootPem, payload.origin);
    const signed = check.ok && crypto.verify('sha256', Buffer.from(JSON.stringify(payload)), check.cert.publicKey, Buffer.from(message.signature, 'base64'));
    if (!signed) {
      this.log(`broadcast ${payload.bid} from ${payload.origin} rejected: ${check.ok ? 'bad signature' : check.reason}`);
      return;
    }
    this.log(`broadcast ← ${payload.origin} via ${fromPeer}: "${payload.text}" (origin signature OK)`);
    this.emit('broadcast', { origin: payload.origin, via: fromPeer, text: payload.text });
    this.#relayBroadcast(message).catch((err) => this.log(`broadcast relay failed: ${err.message}`));
  }

  linkStats() {
    return [...this.links].map(([peer, link]) => ({ peer, ...link.stats }));
  }
}
