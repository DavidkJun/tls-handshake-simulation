import readline from 'node:readline';
import path from 'node:path';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { MeshNode } from './mesh-node.js';
import { CA_URL, PORTS, RADIO, neighborsOf } from './config.js';

const id = process.argv[2];
if (!PORTS[id]) {
  console.error(`usage: node src/cli.js <${Object.keys(PORTS).join('|')}>   (start the CA first: npm run ca)`);
  process.exit(1);
}

const node = new MeshNode(id, { port: PORTS[id], neighbors: neighborsOf(id), ports: PORTS, caUrl: CA_URL, radio: RADIO });
await node.start();
node.connectNeighbors();

node.on('file', async ({ from, name, data }) => {
  const dir = path.join('received', id);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, `${from}-${path.basename(name)}`), data);
});

const help = `commands:
  routes                 routing table
  connect <id>           TLS handshake with any node
  msg <id> <text>        chat message over the secure channel
  file <id> <path>       send a text file
  bcast <text>           broadcast to every node
  sessions               established sessions
  drop <id>              disconnect a radio link
  stats                  radio link counters`;
console.log(help);

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', async (line) => {
  const [cmd, arg, ...rest] = line.trim().split(' ');
  try {
    switch (cmd) {
      case 'routes':
        for (const [dst, r] of node.routes) console.log(`  ${dst}: next=${r.next} hops=${r.hops} path=${r.path.join('→')}`);
        break;
      case 'connect':
        await node.handshake(arg);
        break;
      case 'msg':
        await node.sendChat(arg, rest.join(' '));
        break;
      case 'file':
        await node.sendFile(arg, path.basename(rest[0]), await readFile(rest[0]));
        break;
      case 'bcast':
        await node.broadcast([arg, ...rest].join(' '));
        break;
      case 'sessions':
        for (const s of node.sessions.values()) console.log(`  ${s.sid} peer=${s.peer} role=${s.role} established=${s.established}`);
        break;
      case 'drop':
        node.dropLink(arg);
        break;
      case 'stats':
        console.table(node.linkStats());
        break;
      case '':
        break;
      default:
        console.log(help);
    }
  } catch (err) {
    console.log(`error: ${err.message}`);
  }
});
