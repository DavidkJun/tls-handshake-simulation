import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { createRootCa, createCsr, generateRsaKeys, issueCertificate, verifyCertificate, ROOT_CA_NAME } from '../src/pki.js';
import { RadioLink } from '../src/link.js';

test('certificate issued by the root CA passes verification', () => {
  const ca = createRootCa();
  const cert = issueCertificate(ca, createCsr('E', generateRsaKeys()));
  const result = verifyCertificate(cert.pem, ca.certPem, 'E');
  assert.ok(result.ok, result.reason);
  assert.equal(result.cn, 'E');
});

test('certificate from a rogue CA with the same name is rejected', () => {
  const ca = createRootCa();
  const rogue = createRootCa(ROOT_CA_NAME);
  const fake = issueCertificate(rogue, createCsr('E', generateRsaKeys()));
  assert.match(verifyCertificate(fake.pem, ca.certPem, 'E').reason, /trusted root/);
});

test('certificate for another node is rejected', () => {
  const ca = createRootCa();
  const cert = issueCertificate(ca, createCsr('C', generateRsaKeys()));
  assert.match(verifyCertificate(cert.pem, ca.certPem, 'E').reason, /issued to "C"/);
});

test('radio link never sends a frame larger than the MTU and reassembles the message', async () => {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const accepted = once(server, 'connection');
  const clientSocket = net.connect(server.address().port, '127.0.0.1');
  const [serverSocket] = await accepted;

  const radio = { mtu: 32, bitrate: 1_000_000 };
  const sender = new RadioLink(clientSocket, radio);
  const receiver = new RadioLink(serverSocket, radio);

  const message = Buffer.from('x'.repeat(500));
  const frames = sender.send(message);
  const [got] = await once(receiver, 'message');

  assert.equal(frames, Math.ceil(500 / (32 - 10)));
  assert.deepEqual(got, message);
  assert.equal(receiver.stats.framesIn, frames);
  assert.ok(sender.stats.bytesOut <= frames * 32);
  sender.close();
  receiver.close();
  server.close();
});
