import crypto from 'node:crypto';
import forge from 'node-forge';

export const ROOT_CA_NAME = 'KPI Mesh Root CA';

export function generateRsaKeys() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
}

/** PKCS#10 certificate signing request: proves that the node owns the private key for the public key it wants certified. */
export function createCsr(id, { publicKey, privateKey }) {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = forge.pki.publicKeyFromPem(publicKey);
  csr.setSubject([
    { name: 'commonName', value: id },
    { name: 'organizationName', value: 'KPI Mesh' },
  ]);
  csr.sign(forge.pki.privateKeyFromPem(privateKey), forge.md.sha256.create());
  return forge.pki.certificationRequestToPem(csr);
}

/** Creates a self-signed root certificate. Also used by the demo to build a rogue CA with the same name. */
export function createRootCa(name = ROOT_CA_NAME) {
  const keys = generateRsaKeys();
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(keys.publicKey);
  cert.serialNumber = '01' + crypto.randomBytes(8).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 3600 * 1000);
  const subject = [
    { name: 'commonName', value: name },
    { name: 'organizationName', value: 'KPI Mesh' },
    { name: 'countryName', value: 'UA' },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);
  const signingKey = forge.pki.privateKeyFromPem(keys.privateKey);
  cert.sign(signingKey, forge.md.sha256.create());
  return { cert, signingKey, certPem: forge.pki.certificateToPem(cert) };
}

/** Signs a CSR with the CA key and returns an X.509 v3 end-entity certificate. */
export function issueCertificate(ca, csrPem, { days = 30 } = {}) {
  const csr = forge.pki.certificationRequestFromPem(csrPem);
  if (!csr.verify()) throw new Error('CSR signature is invalid');
  const id = csr.subject.getField('CN')?.value;
  const cert = forge.pki.createCertificate();
  cert.publicKey = csr.publicKey;
  cert.serialNumber = '02' + crypto.randomBytes(8).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + days * 24 * 3600 * 1000);
  cert.setSubject(csr.subject.attributes);
  cert.setIssuer(ca.cert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
    { name: 'subjectAltName', altNames: [{ type: 2, value: `${id}.mesh.local` }] },
    { name: 'authorityKeyIdentifier', keyIdentifier: ca.cert.generateSubjectKeyIdentifier().getBytes() },
  ]);
  cert.sign(ca.signingKey, forge.md.sha256.create());
  return { id, serial: cert.serialNumber.toUpperCase(), pem: forge.pki.certificateToPem(cert) };
}

export function commonName(x509) {
  const match = /(?:^|\n)CN=([^\n]+)/.exec(x509.subject);
  return match ? match[1] : null;
}

/**
 * Offline part of certificate validation: chain to the trusted root, validity period, identity.
 * Revocation can only be answered by the CA, see the /verify endpoint.
 */
export function verifyCertificate(certPem, rootPem, expectedId, now = new Date()) {
  let cert;
  try {
    cert = new crypto.X509Certificate(certPem);
  } catch {
    return { ok: false, reason: 'malformed certificate' };
  }
  const root = new crypto.X509Certificate(rootPem);
  if (!cert.checkIssued(root) || !cert.verify(root.publicKey)) {
    return { ok: false, reason: 'signature does not belong to the trusted root CA' };
  }
  if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
    return { ok: false, reason: 'certificate is expired or not yet valid' };
  }
  const cn = commonName(cert);
  if (expectedId && cn !== expectedId) {
    return { ok: false, reason: `certificate is issued to "${cn}", expected "${expectedId}"` };
  }
  return { ok: true, cert, cn, serial: cert.serialNumber.toUpperCase() };
}
