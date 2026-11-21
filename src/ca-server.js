import { startCaServer } from './ca.js';
import { CA_PORT, PORTS } from './config.js';

await startCaServer({
  port: CA_PORT,
  allowedIds: Object.keys(PORTS),
  log: (msg) => console.log(`[CA] ${msg}`),
});
