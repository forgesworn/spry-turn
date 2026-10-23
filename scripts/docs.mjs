#!/usr/bin/env node
// Keep the short index and complete AI context aligned with maintained guides.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repository = 'https://github.com/forgesworn/spry-turn';
const canonical = `${repository}/blob/main/`;
const version = readFileSync(resolve(root, 'Cargo.toml'), 'utf8')
  .match(/^version = "([^"]+)"$/m)?.[1];
if (!version) throw new Error('Cargo package version is missing');
const write = process.argv.slice(2).includes('--write');
if (process.argv.slice(2).some(arg => arg !== '--write')) {
  throw new Error('Usage: node scripts/docs.mjs [--write]');
}

const documents = [
  ['Get started', 'README.md', 'Overview', 'Scope, features, quick commands and measured performance.'],
  ['Get started', 'docs/README.md', 'Documentation index', 'Choose installation, integration, API or operator guidance.'],
  ['Get started', 'docs/getting-started.md', 'Getting started', 'Authorised source checkout, local server, credentials and TLS.'],
  ['Get started', 'docs/integration.md', 'Client and host integration', 'Browser ICE, native clients, Rust embedding and WASM example.'],
  ['Get started', 'docs/api.md', 'Rust and WASM API', 'Cargo features, configuration, native methods and PacketArena.'],
  ['Get started', 'docs/coturn-compatibility.md', 'Coturn compatibility', 'Feature map, configuration concepts and migration gaps.'],
  ['Operate and support', 'docs/operations.md', 'Independent operation', 'Bounded relay ports, firewall/NAT plan, secret rotation, TLS and limits.'],
  ['Operate and support', 'SECURITY.md', 'Security', 'Reporting channel and transport/credential boundaries.'],
  ['Operate and support', 'SUPPORT.md', 'Support and donations', 'Bug reports and established ForgeSworn funding destinations.'],
  ['Evidence and status', 'docs/benchmarks.md', 'Native M4 benchmarks', 'Matched ARM64 coturn comparison, raw evidence and resource trade-offs.'],
  ['Evidence and status', 'docs/qualification-0.2.1.md', 'Current standalone qualification', 'Bounded-port UDP/TCP/TLS measurements, controlled tuning, latency and resource limits.'],
  ['Evidence and status', 'docs/kithmoot-acceptance.md', 'KithMoot acceptance', 'Actual web application with operator credentials, generated media and explicit physical-phone gates.'],
  ['Evidence and status', 'docs/performance-experiments.md', 'Performance experiments', 'Separate Linux batching, process scaling and profile-guided experiments; no implied runtime integration.'],
  ['Evidence and status', 'docs/verification.md', 'Verification', 'Actual local/CI evidence and explicitly unqualified gates.'],
  ['Evidence and status', 'GOALS.md', 'Acceptance and roadmap', 'Completed standalone work, missing coturn features and later integrations.'],
  ['Evidence and status', 'CHANGELOG.md', 'Changelog', 'Current and historical private prerelease contents.'],
  ['Optional', 'CONTRIBUTING.md', 'Contributing', 'Validation, synthetic fixtures, performance evidence and cleanup.'],
  ['Optional', 'AGENTS.md', 'Coding-agent instructions', 'Repository privacy, safe Rust and required checks.'],
  ['Optional', 'docs/maintaining-docs.md', 'Maintaining documentation', 'Generation, link checks, metadata, privacy and shipment.'],
  ['Optional', 'docs/legal/transport-position.md', 'Transport position', 'Publisher/operator role and unresolved legal interpretations.'],
];
const summary = [
  '# spry-turn',
  '',
  '> Lightweight Rust STUN/TURN server, embeddable native relay and WASM packet codec. MIT; maintained by TheCryptoDonkey under ForgeSworn.',
  '',
  `Version ${version}. Repository and initial GitHub prerelease are private; authorised access is required for source and release artefacts. There is no crates.io, docs.rs or npm publication, hosted relay, credential service or public documentation site.`,
  '',
  'Native UDP/TCP clients and optional TLS use UDP peer allocations. Browser applications use their existing WebRTC ICE implementation. Ordinary browser WASM cannot host a raw-socket TURN server. Shared TURN secrets belong only to trusted operator tools; give clients short-lived credentials.',
  '',
  'This is an initial implementation, without full coturn parity or production qualification. UDP peer-relay port ranges are optional and fail closed on exhaustion. Static user databases, TCP relay allocations, DTLS, dual allocations and deployed Archy/Sapflow integration are not implemented. Physical phone and public-network acceptance remain open.',
  '',
  'The full v0.2.1 native ARM64 M4 Max loopback matrix measured 16–22% higher UDP delivery rate and 27–35% higher TLS delivery rate than the tested coturn configuration; TCP ranged from 1.2% behind to 8.5% ahead. Linux VM results differ, including UDP regressions. These are workload results, not maximum WAN capacity. Stream and kernel socket memory have separate costs. Consult current qualification and raw evidence before reusing figures.',
  '',
  'These files provide navigation and source context for authorised readers and tools. They do not change repository visibility or guarantee indexing by search engines or language models.',
  '',
].join('\n');

let index = summary;
let group;
for (const [section, path, title, description] of documents) {
  if (section !== group) {
    index += `\n## ${section}\n\n`;
    group = section;
  }
  index += `- [${title}](${canonical}${path}): ${description}\n`;
}
index += `- [MIT licence](${canonical}LICENSE): Licence for original source.\n`;
index += `- [Complete documentation context](${canonical}llms-full.txt): Generated source guides with absolute links.\n`;

function absoluteLinks(markdown, source) {
  return markdown.replace(/(!?\[[^\]\n]*\]\()([^\s)]+)(\))/g, (match, prefix, href, suffix) => {
    if (/^[a-z][a-z\d+.-]*:/i.test(href) || href.startsWith('//')) return match;
    const url = new URL(href, `${canonical}${source}`);
    if (!url.href.startsWith(canonical)) throw new Error(`Link escapes canonical tree: ${source}: ${href}`);
    return `${prefix}${url.href}${suffix}`;
  });
}

let full = `${summary}\nGenerated by scripts/docs.mjs; edit source guides and run npm run docs:generate.\n`;
for (const [, path, title] of documents) {
  const source = readFileSync(resolve(root, path), 'utf8').trim();
  full += `\n---\n\n## Source: ${title}\n\nCanonical source: [${path}](${canonical}${path})\n\n${absoluteLinks(source, path)}\n`;
}

const errors = [];
for (const [path, content] of [['llms.txt', index], ['llms-full.txt', full]]) {
  if (write) writeFileSync(resolve(root, path), content);
  else {
    let current;
    try { current = readFileSync(resolve(root, path), 'utf8'); } catch { /* Report missing output as stale. */ }
    if (current !== content) errors.push(`${path} is stale; run npm run docs:generate`);
  }
}

const files = new Set(execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
  { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean));
const read = path => readFileSync(resolve(root, path), 'utf8');
const withoutCode = text => text.replace(/^(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\1[^\n]*$/gm, '');
const headings = new Map();
function anchors(path) {
  if (headings.has(path)) return headings.get(path);
  const found = new Set();
  const counts = new Map();
  for (const heading of withoutCode(read(path)).matchAll(/^#{1,6}\s+(.+?)\s*#*$/gm)) {
    const slug = heading[1].toLowerCase().replace(/<[^>]+>/g, '')
      .replace(/[^\p{L}\p{N}\p{M}\s_-]/gu, '').replace(/\s/g, '-');
    const count = counts.get(slug) ?? 0;
    counts.set(slug, count + 1);
    found.add(`${slug}${count ? `-${count}` : ''}`);
  }
  headings.set(path, found);
  return found;
}

let links = 0;
for (const path of [...files].filter(path => /\.(md|txt)$/.test(path) && !['THIRD_PARTY_LICENSES.txt'].includes(path))) {
  const markdown = withoutCode(read(path));
  for (const match of markdown.matchAll(/!?\[[^\]\n]*\]\(([^\s)]+)\)/g)) {
    let href = match[1];
    let base = dirname(path);
    if (href.startsWith(canonical)) { href = href.slice(canonical.length); base = '.'; }
    else if (/^[a-z][a-z\d+.-]*:/i.test(href) || href.startsWith('//')) continue;
    const [target, fragment] = href.split('#');
    const dest = target ? relative(root, resolve(root, base, decodeURIComponent(target.split('?')[0]))) : path;
    links++;
    if (isAbsolute(dest) || dest === '..' || dest.startsWith(`..${sep}`) || !files.has(dest)) {
      errors.push(`${path}: missing repository target ${href}`);
    } else if (fragment && /\.(md|txt)$/.test(dest) && !anchors(dest).has(decodeURIComponent(fragment))) {
      errors.push(`${path}: missing heading ${href}`);
    }
  }
}

const funding = read('.github/FUNDING.yml');
for (const expected of ['github: TheCryptoDonkey', 'ko_fi: brays', 'https://geyser.fund/project/forgesworn']) {
  if (!funding.includes(expected)) errors.push(`FUNDING.yml: missing established destination ${expected}`);
}
for (const path of ['README.md', 'SUPPORT.md']) {
  for (const destination of ['https://github.com/sponsors/TheCryptoDonkey', 'https://ko-fi.com/brays',
    'https://geyser.fund/project/forgesworn', 'profusemeat89@walletofsatoshi.com']) {
    if (!read(path).includes(destination)) errors.push(`${path}: funding destination missing: ${destination}`);
  }
}
if (!read('docs/README.md').includes('../llms.txt') || !read('docs/README.md').includes('../llms-full.txt')) {
  errors.push('Documentation index must link both LLM entry points');
}
if (errors.length) {
  for (const error of errors) console.error(error);
  process.exitCode = 1;
} else {
  console.log(`Documentation ${write ? 'generated and checked' : 'checked'}: ${documents.length} source guides, ${links} repository links, funding consistent, generated context current.`);
}
