// From-scratch git object, packfile and pkt-line implementation (stdlib only).
// No git binary, no deltas on the wire out (packs we send are full objects),
// but incoming packs are fully decoded including OFS_DELTA / REF_DELTA.

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

export type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';
export interface GitObject { type: GitObjectType; data: Buffer; }

const TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
export const ZERO_OID = '0'.repeat(40);
const HEX40 = /^[0-9a-f]{40}$/;
export function isOid(v: string): boolean { return HEX40.test(v); }

export function hashObject(type: GitObjectType, data: Uint8Array): string {
  const body = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const h = createHash('sha1');
  h.update(Buffer.from(`${type} ${body.length}\0`, 'utf8'));
  h.update(body);
  return h.digest('hex');
}

export interface TreeEntry { mode: string; name: string; oid: string; }

export function parseTree(data: Uint8Array): TreeEntry[] {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < buf.length) {
    const sp = buf.indexOf(0x20, off);
    const nul = buf.indexOf(0x00, sp + 1);
    if (sp < 0 || nul < 0 || nul + 21 > buf.length) throw new Error('bad tree entry');
    entries.push({
      mode: buf.subarray(off, sp).toString('ascii'),
      name: buf.subarray(sp + 1, nul).toString('utf8'),
      oid: buf.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const l = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const r = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(l, r);
}

export function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

export interface CommitView { tree: string; parents: string[]; author: string; committer: string; message: string; }

export function parseCommit(data: Uint8Array): CommitView {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const blank = buf.indexOf('\n\n');
  const headEnd = blank < 0 ? buf.length : blank;
  const message = blank < 0 ? '' : buf.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of buf.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const val = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'tree') tree = val;
    else if (key === 'parent') parents.push(val);
    else if (key === 'author') author = val;
    else if (key === 'committer') committer = val;
  }
  if (!isOid(tree)) throw new Error('commit has no valid tree');
  return { tree, parents, author, committer, message };
}

export function buildCommit(tree: string, parents: readonly string[], message: string, author: string, committer: string, timestamp: number): Buffer {
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${author} ${timestamp} +0000`, `committer ${committer} ${timestamp} +0000`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

export interface TagView { object: string; type: GitObjectType; tag: string; tagger: string; message: string; }

export function parseTag(data: Uint8Array): TagView {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const blank = buf.indexOf('\n\n');
  const headEnd = blank < 0 ? buf.length : blank;
  const headers = new Map<string, string>();
  for (const line of buf.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    headers.set(line.slice(0, sp), line.slice(sp + 1));
  }
  const object = headers.get('object') ?? '';
  const type = headers.get('type') ?? '';
  if (!isOid(object)) throw new Error('tag has no valid object');
  if (type !== 'commit' && type !== 'tree' && type !== 'blob' && type !== 'tag') throw new Error('tag has bad type');
  return { object, type: type as GitObjectType, tag: headers.get('tag') ?? '', tagger: headers.get('tagger') ?? '', message: blank < 0 ? '' : buf.subarray(blank + 2).toString('utf8') };
}

/** Every object reachable from roots (commit -> tree+parents, tree -> entries, tag -> target). */
export function collectReachable(roots: Iterable<string>, lookup: (oid: string) => GitObject | undefined, allowMissing = false): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const r of roots) if (isOid(r)) queue.push(r);
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const obj = lookup(oid);
    if (!obj) {
      if (allowMissing) continue;
      throw new Error(`object ${oid} is missing from the store`);
    }
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      queue.push(c.tree);
      for (const p of c.parents) queue.push(p);
    } else if (obj.type === 'tag') {
      queue.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) if (e.mode !== '160000') queue.push(e.oid);
    }
  }
  return seen;
}

// ---------------------------------------------------------------- pkt-line

export function pktLine(payload: string | Uint8Array): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
export const pktFlush = (): Buffer => Buffer.from('0000', 'ascii');
export const pktDelim = (): Buffer => Buffer.from('0001', 'ascii');

export type Pkt = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'response-end' };

/** Decode all pkt-lines in a buffer; stops at the first trailing partial line or at
 *  the first bytes that are not a pkt-line (e.g. a packfile following a flush in a
 *  receive-pack body — the pack starts with "PACK", which is not a hex length). */
export function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const lenHex = buf.subarray(off, off + 4).toString('ascii');
    const len = parseInt(lenHex, 16);
    if (Number.isNaN(len) || len < 0 || len === 3) break;
    if (len === 0) { out.push({ kind: 'flush' }); off += 4; continue; }
    if (len === 1) { out.push({ kind: 'delim' }); off += 4; continue; }
    if (len === 2) { out.push({ kind: 'response-end' }); off += 4; continue; }
    if (off + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// ---------------------------------------------------------------- packfile

function adler32(data: Buffer): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < data.length; i += 1) {
    a = (a + data[i]!) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

/** Inflate the zlib stream starting at `offset`; returns data + offset just past the stream.
 *  inflateSync ignores trailing bytes, so one call on the remainder yields the data; the stream
 *  ends with the 4-byte adler32 of that data, so scanning for it (and verifying the candidate
 *  prefix inflates to the same data) finds the end in ~2 inflates instead of a binary search.
 *  A binary search remains as the fallback for malformed input. */
function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const data = inflateSync(buf.subarray(offset));
  const needle = Buffer.alloc(4);
  needle.writeUInt32BE(adler32(data), 0);
  let searchFrom = offset + 2;
  for (;;) {
    const idx = buf.indexOf(needle, searchFrom);
    if (idx < 0 || idx + 4 > buf.length) break;
    const end = idx + 4;
    try {
      if (inflateSync(buf.subarray(offset, end)).equals(data)) return { data, next: end };
    } catch { /* not the real end; keep scanning */ }
    searchFrom = idx + 1;
  }
  let lo = offset + 1;
  let hi = buf.length;
  let ans = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    try {
      inflateSync(buf.subarray(offset, mid));
      ans = mid;
      hi = mid - 1;
    } catch {
      lo = mid + 1;
    }
  }
  if (ans < 0) throw new Error('pack entry zlib stream is truncated or corrupt');
  return { data: inflateSync(buf.subarray(offset, ans)), next: ans };
}

function readVarintSize(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let b = buf[start];
  const first = b;
  let size = b & 0x0f;
  let shift = 4;
  let next = start + 1;
  while (b & 0x80) {
    b = buf[next];
    next += 1;
    size |= (b & 0x7f) << shift;
    shift += 7;
  }
  return { size, next, first };
}

function readOfsDeltaBase(buf: Buffer, start: number): { baseOffset: number; next: number } {
  let b = buf[start];
  let next = start + 1;
  let offset = b & 0x7f;
  while (b & 0x80) {
    b = buf[next];
    next += 1;
    offset = ((offset + 1) << 7) | (b & 0x7f);
  }
  return { baseOffset: offset, next };
}

export function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const readVarint = (): number => {
    let out = 0;
    let shift = 0;
    for (;;) {
      const b = delta[pos++];
      out |= (b & 0x7f) << shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return out;
  };
  const srcSize = readVarint();
  const tgtSize = readVarint();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const parts: Buffer[] = [];
  let total = 0;
  while (pos < delta.length) {
    const op = delta[pos++];
    if (op & 0x80) {
      let off = 0;
      let size = 0;
      if (op & 0x01) off = delta[pos++];
      if (op & 0x02) off |= delta[pos++] << 8;
      if (op & 0x04) off |= delta[pos++] << 16;
      if (op & 0x08) off |= delta[pos++] << 24;
      if (op & 0x10) size = delta[pos++];
      if (op & 0x20) size |= delta[pos++] << 8;
      if (op & 0x40) size |= delta[pos++] << 16;
      if (size === 0) size = 0x10000;
      parts.push(base.subarray(off, off + size));
      total += size;
    } else if (op !== 0) {
      parts.push(delta.subarray(pos, pos + op));
      total += op;
      pos += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (total !== tgtSize) throw new Error('delta target size mismatch');
  return Buffer.concat(parts);
}

export interface PackReadResult { objects: Map<string, GitObject>; deltaCount: number; declaredCount: number; version: number; }

/** Read a packfile; resolveBase supplies objects a thin pack's REF_DELTA may need. */
export function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObject | undefined): PackReadResult {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  const declaredCount = pack.readUInt32BE(8);
  // Trailer check is the caller's job; we verify it in writePack/verify paths.
  interface RawEntry { type: GitObjectType | 'ofs' | 'ref'; data: Buffer; baseOffset?: number; baseOid?: string; offset: number; }
  const raw: RawEntry[] = [];
  let off = 12;
  for (let i = 0; i < declaredCount; i += 1) {
    const entryOffset = off;
    const { size, next, first } = readVarintSize(pack, off);
    off = next;
    const typeCode = (first >> 4) & 0x07;
    if (typeCode === 6) {
      const { baseOffset, next: n2 } = readOfsDeltaBase(pack, off);
      off = n2;
      const { data, next: n3 } = inflateAt(pack, off);
      off = n3;
      raw.push({ type: 'ofs', data, baseOffset: entryOffset - baseOffset, offset: entryOffset });
      void size;
    } else if (typeCode === 7) {
      const baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
      const { data, next: n3 } = inflateAt(pack, off);
      off = n3;
      raw.push({ type: 'ref', data, baseOid, offset: entryOffset });
      void size;
    } else {
      const type = CODE_TYPE[typeCode];
      if (!type) throw new Error(`pack entry type ${typeCode}`);
      const { data, next: n3 } = inflateAt(pack, off);
      off = n3;
      if (data.length !== size) throw new Error('pack entry size mismatch');
      raw.push({ type, data, offset: entryOffset });
    }
  }
  const objects = new Map<string, GitObject>();
  const byOffset = new Map<number, string>();
  // First pass: plain objects.
  for (const e of raw) {
    if (e.type === 'commit' || e.type === 'tree' || e.type === 'blob' || e.type === 'tag') {
      const oid = hashObject(e.type, e.data);
      objects.set(oid, { type: e.type, data: e.data });
      byOffset.set(e.offset, oid);
    }
  }
  let deltaCount = 0;
  // Resolve deltas (possibly chained); iterate until no progress.
  const pending = raw.filter((e) => e.type === 'ofs' || e.type === 'ref');
  let progress = true;
  while (pending.length && progress) {
    progress = false;
    for (let i = pending.length - 1; i >= 0; i -= 1) {
      const e = pending[i]!;
      let baseObj: GitObject | undefined;
      let baseOid: string | undefined;
      if (e.type === 'ofs') {
        baseOid = byOffset.get(e.baseOffset!);
        if (baseOid) baseObj = objects.get(baseOid);
      } else {
        baseOid = e.baseOid;
        baseObj = objects.get(baseOid!) ?? resolveBase?.(baseOid!);
      }
      if (!baseObj) continue;
      const data = applyDelta(baseObj.data, e.data);
      const oid = hashObject(baseObj.type, data);
      objects.set(oid, { type: baseObj.type, data });
      byOffset.set(e.offset, oid);
      pending.splice(i, 1);
      deltaCount += 1;
      progress = true;
    }
  }
  if (pending.length) throw new Error('pack has unresolvable deltas');
  return { objects, deltaCount, declaredCount, version };
}

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas). */
export function writePack(objects: Iterable<{ type: GitObjectType; data: Uint8Array }>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const o of list) {
    const data = Buffer.isBuffer(o.data) ? o.data : Buffer.from(o.data);
    parts.push(writePackObjectHeader(o.type, data.length));
    parts.push(deflateSync(data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

export function verifyPackChecksum(pack: Buffer): boolean {
  if (pack.length < 20) return false;
  const actual = pack.subarray(pack.length - 20).toString('hex');
  const expected = createHash('sha1').update(pack.subarray(0, pack.length - 20)).digest('hex');
  return actual === expected;
}

// ---------------------------------------------------------------- tree helpers

/** Flatten a tree (recursive) into path -> {oid, mode}. */
export function flattenTree(rootOid: string, lookup: (oid: string) => GitObject | undefined): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (treeOid: string, prefix: string): void => {
    const obj = lookup(treeOid);
    if (!obj || obj.type !== 'tree') throw new Error(`tree ${treeOid} missing`);
    for (const e of parseTree(obj.data)) {
      const path = prefix ? `${prefix}/${e.name}` : e.name;
      if (e.mode === '40000') walk(e.oid, path);
      else out.set(path, { oid: e.oid, mode: e.mode });
    }
  };
  walk(rootOid, '');
  return out;
}

/** Build (and store) a tree from a flat path map; returns the root tree oid. */
export function buildTreeFromFlat(flat: Map<string, { oid: string; mode: string }>, store: (type: GitObjectType, data: Buffer) => string): string {
  interface Node { files: Map<string, { oid: string; mode: string }>; dirs: Map<string, Node>; }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, entry] of [...flat.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const segs = path.split('/');
    let node = root;
    for (let i = 0; i < segs.length - 1; i += 1) {
      const s = segs[i]!;
      if (!node.dirs.has(s)) node.dirs.set(s, make());
      node = node.dirs.get(s)!;
    }
    node.files.set(segs[segs.length - 1]!, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, e] of node.files) entries.push({ mode: e.mode, name, oid: e.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return store('tree', buildTree(entries));
  };
  return build(root);
}

/** Ancestor set of a commit (including itself). */
export function ancestorsOf(tip: string, lookup: (oid: string) => GitObject | undefined): Set<string> {
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid) || !isOid(oid)) continue;
    const obj = lookup(oid);
    if (!obj || obj.type !== 'commit') continue;
    seen.add(oid);
    for (const p of parseCommit(obj.data).parents) queue.push(p);
  }
  return seen;
}

/** True when `anc` is an ancestor of (or equal to) `tip`. Walks from the tip and
 *  stops as soon as `anc` is found — a fast-forward push's old tip is one step
 *  away, so this is O(new commits), not O(whole history). */
export function isAncestor(anc: string, tip: string, lookup: (oid: string) => GitObject | undefined): boolean {
  if (anc === tip) return true;
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid) || !isOid(oid)) continue;
    seen.add(oid);
    const obj = lookup(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) {
      if (p === anc) return true;
      queue.push(p);
    }
  }
  return false;
}

/** First common ancestor of a and b (BFS from both sides, nearest to a). */
export function mergeBase(a: string, b: string, lookup: (oid: string) => GitObject | undefined): string | null {
  const bAnc = ancestorsOf(b, lookup);
  const queue: string[] = [a];
  const seen = new Set<string>();
  while (queue.length) {
    const oid = queue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (bAnc.has(oid)) return oid;
    const obj = lookup(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) queue.push(p);
  }
  return null;
}
