// Exercise actual WebAssembly, including repeated packet reuse without heap growth.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const root = process.argv[2] ?? '.local/wasm';
const { initSync, PacketArena } = await import(pathToFileURL(`${process.cwd()}/${root}/spry_turn.js`).href);
const wasm = initSync({ module: readFileSync(`${root}/spry_turn_bg.wasm`) });
const arena = new PacketArena(2048);
let bytes = new Uint8Array(wasm.memory.buffer, arena.ptr(), arena.capacity());
const vector = '000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf';
bytes.set(Buffer.from(vector, 'hex'));
assert.equal(arena.valid_stun(vector.length / 2), true);
assert.equal(arena.stun_method(vector.length / 2), 1);
assert.equal(arena.verify_integrity(vector.length / 2, new TextEncoder().encode('VOkJxbRl1RmTxUk/WvJxBt')), true);
bytes = new Uint8Array(wasm.memory.buffer, arena.ptr(), arena.capacity());
bytes[24] ^= 1; assert.equal(arena.valid_stun(vector.length / 2), false);
bytes.fill(0x5a, 4, 1204);
const memoryBefore = wasm.memory.buffer.byteLength;
const started = performance.now();
for (let i = 0; i < 1_000_000; i++) {
  if (!arena.frame_channel(0x4000, 1200) || arena.channel_payload_len(1204) !== 1200) throw new Error('framing failed');
}
const elapsed = performance.now() - started;
assert.equal(wasm.memory.buffer.byteLength, memoryBefore);
assert.equal(arena.channel_number(1204), 0x4000);
assert.equal(arena.frame_channel(0x5000, 1200), false);
assert.equal(arena.frame_channel(0x4000, 65536), false);
assert.equal(arena.valid_stun(65536), false);
arena.free();
console.log(JSON.stringify({ wasm: 'passed', reusedPackets: 1000000, memoryGrew: false, framingAndParsingMs: +elapsed.toFixed(3), note: 'Protocol microbenchmark only; no network forwarding is measured.' }));
