import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { prf, TlsSession } from '../src/tls.js';

test('PRF matches the published TLS 1.2 P_SHA256 test vector', () => {
  const out = prf(Buffer.from('9bbe436ba940f017b17652849a71db35', 'hex'), 'test label', Buffer.from('a0ba9f936cda311827a6f796ffd5198c', 'hex'), 32);
  assert.equal(out.toString('hex'), 'e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a');
});

function handshakePair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const client = new TlsSession({ role: 'client', self: 'A', peer: 'B' });
  const server = new TlsSession({ role: 'server', self: 'B', peer: 'A', sid: client.sid });
  server.receiveClientHello(client.clientHello());
  client.receiveServerHello(server.serverHello('-----CERT-----'));
  server.receiveClientKeyExchange(client.clientKeyExchange(publicKey).body, privateKey);
  server.receiveFinished(client.finished().body);
  client.receiveFinished(server.finished().body);
  return { client, server };
}

test('both sides derive the same master secret and session keys', () => {
  const { client, server } = handshakePair();
  assert.ok(client.established && server.established);
  assert.deepEqual(client.master, server.master);
  assert.deepEqual(client.keys, server.keys);
  assert.notDeepEqual(client.keys.clientWriteKey, client.keys.serverWriteKey);
});

test('records decrypt in both directions', () => {
  const { client, server } = handshakePair();
  assert.equal(server.open(client.seal('app', Buffer.from('ping')), 'app').toString(), 'ping');
  assert.equal(client.open(server.seal('app', Buffer.from('pong')), 'app').toString(), 'pong');
});

test('a modified ciphertext is rejected', () => {
  const { client, server } = handshakePair();
  const record = client.seal('app', Buffer.from('transfer 100'));
  const ct = Buffer.from(record.ct, 'base64');
  ct[0] ^= 1;
  assert.throws(() => server.open({ ...record, ct: ct.toString('base64') }, 'app'), /bad_record_mac/);
});

test('a replayed record is rejected', () => {
  const { client, server } = handshakePair();
  const record = client.seal('app', Buffer.from('once'));
  server.open(record, 'app');
  assert.throws(() => server.open(record, 'app'), /sequence number/);
});

test('Finished fails when the transcripts differ', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const client = new TlsSession({ role: 'client', self: 'A', peer: 'B' });
  const server = new TlsSession({ role: 'server', self: 'B', peer: 'A', sid: client.sid });
  const hello = client.clientHello();
  server.receiveClientHello({ ...hello, suites: [...hello.suites, 'TLS_NULL_WITH_NULL_NULL'] });
  client.receiveServerHello(server.serverHello('-----CERT-----'));
  server.receiveClientKeyExchange(client.clientKeyExchange(publicKey).body, privateKey);
  assert.throws(() => server.receiveFinished(client.finished().body), /verify_data mismatch/);
});
