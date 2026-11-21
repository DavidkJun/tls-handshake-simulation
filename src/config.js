export const CA_PORT = 8800;
export const CA_URL = `http://127.0.0.1:${CA_PORT}`;

export const PORTS = { A: 9101, B: 9102, C: 9103, D: 9104, E: 9105, F: 9106, G: 9107 };

// Not fully connected: most pairs can reach each other only through intermediate nodes.
export const LINKS = [
  ['A', 'B'],
  ['A', 'C'],
  ['B', 'D'],
  ['C', 'D'],
  ['C', 'E'],
  ['D', 'F'],
  ['E', 'F'],
  ['F', 'G'],
];

// Slow radio: every frame (header included) is at most `mtu` bytes and takes
// frame.length * 8 / bitrate seconds of airtime.
export const RADIO = { mtu: 96, bitrate: 57600 };

export function neighborsOf(id, links = LINKS) {
  return links
    .filter(([a, b]) => a === id || b === id)
    .map(([a, b]) => (a === id ? b : a))
    .sort();
}
