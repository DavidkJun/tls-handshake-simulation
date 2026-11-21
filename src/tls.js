import crypto from 'node:crypto';

// Real TLS 1.2 suite (RFC 5288): RSA key transport, AES-128-GCM records, SHA-256 PRF.
export const SUITE = 'TLS_RSA_WITH_AES_128_GCM_SHA256';
const KEY_LEN = 16;
const IV_LEN = 4;

const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();

/** TLS 1.2 PRF (RFC 5246, section 5): P_SHA256(secret, label + seed). */
export function prf(secret, label, seed, length) {
  const labelSeed = Buffer.concat([Buffer.from(label, 'ascii'), seed]);
  const out = [];
  let produced = 0;
  let a = labelSeed;
  while (produced < length) {
    a = hmac(secret, a);
    const block = hmac(secret, Buffer.concat([a, labelSeed]));
    out.push(block);
    produced += block.length;
  }
  return Buffer.concat(out).subarray(0, length);
}

export const short = (buf, n = 8) => buf.toString('hex').slice(0, n * 2) + '…';

/**
 * State of one TLS session between two nodes. Network-agnostic: every method returns the message
 * body to send or consumes a received one, so the same class is used by mesh nodes and unit tests.
 */
export class TlsSession {
  constructor({ role, self, peer, sid = crypto.randomBytes(6).toString('hex') }) {
    this.role = role;
    this.self = self;
    this.peer = peer;
    this.sid = sid;
    this.transcript = [];
    this.seqOut = 0;
    this.seqIn = 0;
    this.established = false;
    this.startedAt = Date.now();
  }

  #remember(body) {
    this.transcript.push(JSON.stringify(body));
  }

  #transcriptHash() {
    return crypto.createHash('sha256').update(this.transcript.join('\n')).digest();
  }

  // (1) client -> server
  clientHello() {
    this.clientRandom = crypto.randomBytes(32);
    const body = { type: 'client_hello', sid: this.sid, version: 'TLS1.2', random: this.clientRandom.toString('base64'), suites: [SUITE] };
    this.#remember(body);
    return body;
  }

  receiveClientHello(body) {
    if (!body.suites.includes(SUITE)) throw new Error('no common cipher suite');
    this.clientRandom = Buffer.from(body.random, 'base64');
    this.#remember(body);
  }

  // (2) server -> client: server random + X.509 certificate with the server's RSA public key
  serverHello(certificatePem) {
    this.serverRandom = crypto.randomBytes(32);
    const body = { type: 'server_hello', sid: this.sid, random: this.serverRandom.toString('base64'), suite: SUITE, certificate: certificatePem };
    this.#remember(body);
    return body;
  }

  receiveServerHello(body) {
    this.serverRandom = Buffer.from(body.random, 'base64');
    this.#remember(body);
  }

  // (4) client -> server: premaster secret encrypted with the public key from the verified certificate
  clientKeyExchange(serverPublicKey) {
    const premaster = Buffer.concat([Buffer.from([0x03, 0x03]), crypto.randomBytes(46)]);
    const encrypted = crypto.publicEncrypt({ key: serverPublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, premaster);
    const body = { type: 'client_key_exchange', sid: this.sid, encrypted_premaster: encrypted.toString('base64') };
    this.#remember(body);
    this.#deriveKeys(premaster);
    return { body, premasterLength: premaster.length, encryptedLength: encrypted.length };
  }

  receiveClientKeyExchange(body, privateKey) {
    const premaster = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(body.encrypted_premaster, 'base64'),
    );
    this.#remember(body);
    this.#deriveKeys(premaster);
    return { premasterLength: premaster.length };
  }

  // (5) both sides: master secret and session keys from client random, server random and premaster
  #deriveKeys(premaster) {
    this.master = prf(premaster, 'master secret', Buffer.concat([this.clientRandom, this.serverRandom]), 48);
    const block = prf(this.master, 'key expansion', Buffer.concat([this.serverRandom, this.clientRandom]), 2 * KEY_LEN + 2 * IV_LEN);
    this.keys = {
      clientWriteKey: block.subarray(0, KEY_LEN),
      serverWriteKey: block.subarray(KEY_LEN, 2 * KEY_LEN),
      clientIv: block.subarray(2 * KEY_LEN, 2 * KEY_LEN + IV_LEN),
      serverIv: block.subarray(2 * KEY_LEN + IV_LEN),
    };
    this.premasterFingerprint = short(crypto.createHash('sha256').update(premaster).digest());
    premaster.fill(0);
  }

  // (6) "ready" message encrypted with the session key; verify_data proves both saw the same handshake
  finished() {
    const label = this.role === 'client' ? 'client finished' : 'server finished';
    const verifyData = prf(this.master, label, this.#transcriptHash(), 12).toString('hex');
    this.transcript.push(`${label}:${verifyData}`);
    return { body: { type: 'finished', sid: this.sid, ...this.seal('finished', Buffer.from(JSON.stringify({ msg: 'ready', verify_data: verifyData }))) }, verifyData };
  }

  receiveFinished(body) {
    const { msg, verify_data: received } = JSON.parse(this.open(body, 'finished'));
    const label = this.role === 'client' ? 'server finished' : 'client finished';
    const expected = prf(this.master, label, this.#transcriptHash(), 12);
    if (msg !== 'ready' || !crypto.timingSafeEqual(expected, Buffer.from(received, 'hex'))) {
      throw new Error('Finished verify_data mismatch: handshake was tampered with');
    }
    this.transcript.push(`${label}:${received}`);
    this.established = true;
    return { verifyData: received };
  }

  // (7) record layer: AES-128-GCM, nonce = implicit IV (4 B) + sequence number (8 B)
  seal(type, plaintext) {
    const client = this.role === 'client';
    const key = client ? this.keys.clientWriteKey : this.keys.serverWriteKey;
    const iv = client ? this.keys.clientIv : this.keys.serverIv;
    const seq = this.seqOut++;
    const cipher = crypto.createCipheriv('aes-128-gcm', key, nonceFor(iv, seq));
    cipher.setAAD(Buffer.from(`${this.sid}|${type}|${seq}`));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { seq, ct: ct.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
  }

  open(record, type) {
    if (record.seq !== this.seqIn) throw new Error(`unexpected record sequence number ${record.seq}, expected ${this.seqIn} (replay or loss)`);
    const client = this.role === 'client';
    const key = client ? this.keys.serverWriteKey : this.keys.clientWriteKey;
    const iv = client ? this.keys.serverIv : this.keys.clientIv;
    const decipher = crypto.createDecipheriv('aes-128-gcm', key, nonceFor(iv, record.seq));
    decipher.setAAD(Buffer.from(`${this.sid}|${type}|${record.seq}`));
    decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
    let plaintext;
    try {
      plaintext = Buffer.concat([decipher.update(Buffer.from(record.ct, 'base64')), decipher.final()]);
    } catch {
      throw new Error('record authentication failed (bad_record_mac): ciphertext was modified');
    }
    this.seqIn++;
    return plaintext;
  }
}

function nonceFor(iv, seq) {
  const nonce = Buffer.alloc(12);
  iv.copy(nonce, 0);
  nonce.writeBigUInt64BE(BigInt(seq), 4);
  return nonce;
}
