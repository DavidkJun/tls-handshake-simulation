import http from 'node:http';
import crypto from 'node:crypto';
import { createRootCa, issueCertificate, commonName } from './pki.js';

/**
 * Certificate authority with an HTTP API:
 *   GET  /root     root certificate (trust anchor that every node pins)
 *   POST /issue    { csr }    -> { cert, serial }   only for registered node ids
 *   POST /verify   { cert }   -> { valid, reason }  signature, validity, registry and revocation check
 *   POST /revoke   { serial } -> { ok }
 *   GET  /crl      list of revoked serial numbers
 */
export async function startCaServer({ port, allowedIds, log = () => {} }) {
  const ca = createRootCa();
  const rootX509 = new crypto.X509Certificate(ca.certPem);
  const issued = new Map(); // serial -> { id, pem }
  const revoked = new Set();
  log(`root certificate "${commonName(rootX509)}" serial=${rootX509.serialNumber} sha256=${rootX509.fingerprint256.slice(0, 23)}…`);

  function verify(pem) {
    let cert;
    try {
      cert = new crypto.X509Certificate(pem);
    } catch {
      return { valid: false, reason: 'malformed certificate' };
    }
    const serial = cert.serialNumber.toUpperCase();
    const subject = commonName(cert);
    if (!cert.verify(rootX509.publicKey)) return { valid: false, serial, subject, reason: 'not signed by this CA' };
    const now = new Date();
    if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) return { valid: false, serial, subject, reason: 'expired' };
    if (!issued.has(serial)) return { valid: false, serial, subject, reason: 'unknown serial number' };
    if (revoked.has(serial)) return { valid: false, serial, subject, reason: 'certificate is revoked' };
    return { valid: true, serial, subject, reason: 'ok' };
  }

  const routes = {
    'GET /root': () => ({ pem: ca.certPem }),
    'GET /crl': () => ({ revoked: [...revoked] }),
    'POST /issue': ({ csr }) => {
      const cert = issueCertificate(ca, csr);
      if (!allowedIds.includes(cert.id)) throw new Error(`node "${cert.id}" is not registered`);
      issued.set(cert.serial, cert);
      log(`issued certificate CN=${cert.id} serial=${cert.serial}`);
      return { cert: cert.pem, serial: cert.serial };
    },
    'POST /verify': ({ cert }) => {
      const result = verify(cert);
      log(`verify CN=${result.subject} serial=${result.serial} -> ${result.valid ? 'VALID' : 'INVALID: ' + result.reason}`);
      return result;
    },
    'POST /revoke': ({ serial }) => {
      revoked.add(serial.toUpperCase());
      log(`revoked serial=${serial.toUpperCase()} (CN=${issued.get(serial.toUpperCase())?.id})`);
      return { ok: true };
    },
  };

  const server = http.createServer(async (req, res) => {
    const handler = routes[`${req.method} ${req.url}`];
    if (!handler) {
      res.writeHead(404).end();
      return;
    }
    try {
      let body = '';
      for await (const chunk of req) body += chunk;
      const result = handler(body ? JSON.parse(body) : {});
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(result));
    } catch (err) {
      res.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify({ error: err.message }));
    }
  });
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  log(`listening on http://127.0.0.1:${port}`);
  return { server, ca, close: () => new Promise((resolve) => server.close(resolve)) };
}
