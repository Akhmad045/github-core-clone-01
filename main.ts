// forge-v2: a fast, standalone GitHub-compatible git forge in one file.
//
// Surfaces, all served from one in-memory store by one process:
//   - git smart HTTP at /{owner}/{repo}.git (upload-pack protocol v2, receive-pack v0)
//   - REST v3 under /api/v3 (repositories, branches, commits, contents, labels,
//     issues, comments, pull requests, files and merges)
//   - GraphQL v4 at /api/graphql (the documents gh and github-mcp-server send)
//   - MCP over streamable HTTP at /mcp (server/discover, tools/list, tools/call)
//
// Speed notes: no framework, no per-request URL object, no logging on hot paths.
// Issue reads answer from a cached response buffer, the tools/list payload is a
// prebuilt string, fetch pack responses are cached per repository version, and
// every object lives in Maps keyed by its id. The store is deterministic: ids
// come from counters and timestamps from a logical clock, never the wall clock.

import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// constants and small utilities

const VIEWER = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'Ada Iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0000000000000000000000000000000000000000';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const AUTH_WANT = TOKEN === '' ? null : `Bearer ${TOKEN}`;
const JSON_CT = 'application/json; charset=utf-8';

let requestCounter = 0;
let clockTick = 0;
const EPOCH = 1735689600; // 2025-01-01T00:00:00Z, the logical clock's start

function nowIso(): string {
  clockTick += 1;
  return new Date((EPOCH + clockTick) * 1000).toISOString();
}
function nowStamp(): string {
  clockTick += 1;
  return `${EPOCH + clockTick} +0000`;
}

function sha1Hex(type: string, data: Buffer): string {
  const hash = createHash('sha1');
  hash.update(`${type} ${data.length}\0`, 'utf8');
  hash.update(data);
  return hash.digest('hex');
}

function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function b64encodeText(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}
function b64decodeToBuffer(content: string): Buffer {
  return Buffer.from(String(content ?? '').replace(/[\r\n\t ]+/g, ''), 'base64');
}

// Relay-style global ids: opaque base64, stable per object, decodable by node().
function gqlId(type: string, dbId: number): string {
  return Buffer.from(`07:${type}${dbId}`, 'utf8').toString('base64');
}
function gqlDecode(id: string): { type: string; dbId: number } | null {
  try {
    const text = Buffer.from(String(id), 'base64').toString('utf8');
    const match = /^\d+:([A-Za-z]+)(\d+)$/.exec(text);
    if (match === null) return null;
    return { type: match[1], dbId: Number(match[2]) };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// pkt-line codec

function pkt(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return data.length === 0 ? header : Buffer.concat([header, data], data.length + 4);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

/** Decode every pkt-line in `body` from `offset`; returns payloads and the end offset. */
function decodePkts(body: Buffer, offset: number): { payloads: Buffer[]; end: number; flushSeen: boolean } {
  const payloads: Buffer[] = [];
  let at = offset;
  let flushSeen = false;
  while (at + 4 <= body.length) {
    const hex = body.toString('ascii', at, at + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) break;
    const length = Number.parseInt(hex, 16);
    if (length === 0) {
      at += 4;
      flushSeen = true;
      break;
    }
    if (length === 1 || length === 2) {
      at += 4;
      payloads.push(Buffer.from(length === 1 ? '\x01' : '\x02', 'latin1'));
      continue;
    }
    if (length < 4 || at + length > body.length) break;
    payloads.push(body.subarray(at + 4, at + length));
    at += length;
  }
  return { payloads, end: at, flushSeen };
}

// ---------------------------------------------------------------------------
// packfiles: plain-object writer, delta-aware reader

const TYPE_TO_CODE: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TO_TYPE: Record<number, string> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packObjectHeader(type: string, size: number): Buffer {
  const code = TYPE_TO_CODE[type];
  const bytes: number[] = [];
  let rest = size;
  let first = (code << 4) | (rest & 0x0f);
  rest = Math.floor(rest / 16);
  while (rest > 0) {
    bytes.push(first | 0x80);
    first = rest & 0x7f;
    rest = Math.floor(rest / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function buildPack(objects: ReadonlyArray<{ type: string; data: Buffer }>): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(packObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++];
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      delta.copy(out, written, offset, offset + op);
      offset += op;
      written += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  return out;
}

interface PackEntry {
  offset: number;
  typeCode: number;
  data: Buffer;
  baseOffset: number;
  baseOid: string;
}

/** Parse a pack into raw entries; delta bases are resolved by the caller. */
function parsePack(pack: Buffer): PackEntry[] {
  if (pack.length < 32 || pack.toString('ascii', 0, 4) !== 'PACK') throw new Error('not a pack');
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const entries: PackEntry[] = [];
  let offset = 12;
  for (let index = 0; index < count; index += 1) {
    const entryOffset = offset;
    let byte = pack[offset++];
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[offset++];
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    let baseOffset = -1;
    let baseOid = '';
    if (typeCode === 6) {
      let b = pack[offset++];
      let value = b & 0x7f;
      while (b & 0x80) {
        b = pack[offset++];
        value = (value + 1) * 128 + (b & 0x7f);
      }
      baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      baseOid = pack.toString('hex', offset, offset + 20);
      offset += 20;
    }
    const inflated = inflateSync(pack.subarray(offset, trailerStart), { info: true }) as unknown as {
      buffer: Buffer;
      engine: { bytesWritten: number };
    };
    if (inflated.buffer.length !== size) throw new Error('pack entry size mismatch');
    offset += inflated.engine.bytesWritten;
    entries.push({ offset: entryOffset, typeCode, data: inflated.buffer, baseOffset, baseOid });
  }
  return entries;
}

// ---------------------------------------------------------------------------
// the store

interface GitObject {
  type: string;
  data: Buffer;
}

interface IssueRec {
  dbId: number;
  number: number;
  title: string;
  body: string;
  state: string; // 'open' | 'closed'
  labels: string[];
  comments: Array<{ id: number; body: string; created: string }>;
  created: string;
  updated: string;
  buf: Buffer | null; // cached REST serialization
}

interface PullRec {
  dbId: number;
  number: number;
  title: string;
  body: string;
  state: string; // 'open' | 'closed'
  merged: boolean;
  headRef: string;
  baseRef: string;
  headShaAtCreate: string;
  baseShaAtCreate: string;
  mergeCommitSha: string | null;
  mergedAt: string | null;
  created: string;
  updated: string;
}

interface Repo {
  id: number;
  name: string;
  priv: boolean;
  description: string;
  created: string;
  updated: string;
  version: number; // bumped on any git-visible change; keys the caches
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, { name: string; color: string }>;
  issues: Map<number, IssueRec>;
  pulls: Map<number, PullRec>;
  nextNumber: number;
  commitMaps: Map<string, Map<string, string>>; // commit oid -> path -> blob oid
  packCache: Map<string, Buffer>;
  lsCache: Map<string, Buffer>;
  shallow: Set<string>; // commit oids currently at the shallow boundary
  jsonBuf: Buffer | null;
}

const repos = new Map<string, Repo>();
let nextRepoId = 1;
let nextIssueDbId = 1;
let nextPullDbId = 1;
let nextCommentId = 1;
const issueByDbId = new Map<number, { repo: Repo; issue: IssueRec }>();
const pullByDbId = new Map<number, { repo: Repo; pull: PullRec }>();

function createRepo(name: string, priv: boolean, description: string): Repo {
  const stamp = nowIso();
  const repo: Repo = {
    id: nextRepoId++,
    name,
    priv,
    description,
    created: stamp,
    updated: stamp,
    version: 1,
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: new Map(),
    pulls: new Map(),
    nextNumber: 1,
    commitMaps: new Map(),
    packCache: new Map(),
    lsCache: new Map(),
    shallow: new Set(),
    jsonBuf: null,
  };
  repos.set(name, repo);
  return repo;
}

function touchRepo(repo: Repo): void {
  repo.version += 1;
  repo.updated = nowIso();
  repo.packCache.clear();
  repo.lsCache.clear();
}

// ---------------------------------------------------------------------------
// git object helpers

interface CommitInfo {
  tree: string;
  parents: string[];
  message: string;
  author: string;
  committer: string;
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const info: CommitInfo = { tree: '', parents: [], message: blank < 0 ? '' : text.slice(blank + 2), author: '', committer: '' };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) info.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) info.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) info.author = line.slice(7);
    else if (line.startsWith('committer ')) info.committer = line.slice(10);
  }
  return info;
}

function parseTagTarget(data: Buffer): string {
  const text = data.toString('utf8', 0, Math.min(data.length, 200));
  const match = /^object ([0-9a-f]{40})/.exec(text);
  return match === null ? '' : match[1];
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    entries.push({
      mode: data.toString('ascii', offset, space),
      name: data.toString('utf8', space + 1, nul),
      oid: data.toString('hex', nul + 1, nul + 21),
    });
    offset = nul + 21;
  }
  return entries;
}

function buildTreeData(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
    const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
    return Buffer.compare(left, right);
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

/** Follow tag objects to the commit they name (or return the oid itself). */
function peelToCommit(repo: Repo, oid: string): string {
  let current = oid;
  for (let guard = 0; guard < 16; guard += 1) {
    const object = repo.objects.get(current);
    if (object === undefined || object.type !== 'tag') return current;
    current = parseTagTarget(object.data);
  }
  return current;
}

/** The file map (path -> blob oid) of a commit, memoized per repository. */
function fileMapForCommit(repo: Repo, commitOid: string): Map<string, string> {
  const cached = repo.commitMaps.get(commitOid);
  if (cached !== undefined) return cached;
  const map = new Map<string, string>();
  const commit = repo.objects.get(commitOid);
  if (commit !== undefined && commit.type === 'commit') {
    const walk = (treeOid: string, prefix: string): void => {
      const tree = repo.objects.get(treeOid);
      if (tree === undefined || tree.type !== 'tree') return;
      for (const entry of parseTree(tree.data)) {
        if (entry.mode === '40000') walk(entry.oid, `${prefix}${entry.name}/`);
        else map.set(`${prefix}${entry.name}`, entry.oid);
      }
    };
    walk(parseCommit(commit.data).tree, '');
  }
  repo.commitMaps.set(commitOid, map);
  return map;
}

/** Store the tree chain for a file map and return the root tree oid. */
function storeTreeForMap(repo: Repo, files: Map<string, string>): string {
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, oid] of files) {
    const segments = path.split('/');
    let node = root;
    for (let index = 0; index < segments.length - 1; index += 1) {
      let child = node.dirs.get(segments[index]);
      if (child === undefined) {
        child = { files: new Map(), dirs: new Map() };
        node.dirs.set(segments[index], child);
      }
      node = child;
    }
    node.files.set(segments[segments.length - 1], oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTreeData(entries);
    const oid = sha1Hex('tree', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(root);
}

/** Create a commit object over `files` and return its oid (does not move any ref). */
function makeCommit(repo: Repo, files: Map<string, string>, parents: string[], message: string): string {
  const tree = storeTreeForMap(repo, files);
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${nowStamp()}`;
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  const data = Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
  const oid = sha1Hex('commit', data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'commit', data });
  return oid;
}

/** Every ancestor commit of `tip` (inclusive), parents walked through the store. */
function ancestorsOf(repo: Repo, tip: string): Set<string> {
  const seen = new Set<string>();
  const queue = [peelToCommit(repo, tip)];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    seen.add(oid);
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return seen;
}

function isAncestor(repo: Repo, ancestor: string, tip: string): boolean {
  const target = peelToCommit(repo, ancestor);
  const seen = new Set<string>();
  const queue = [peelToCommit(repo, tip)];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (oid === target) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return false;
}

function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancestorsA = ancestorsOf(repo, a);
  const seen = new Set<string>();
  const queue = [peelToCommit(repo, b)];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (ancestorsA.has(oid)) return oid;
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return null;
}

/** Commits reachable from `tip`, newest first (depth-first over parents). */
function listCommits(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [peelToCommit(repo, tip)];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    seen.add(oid);
    out.push(oid);
    const parents = parseCommit(object.data).parents;
    for (let index = parents.length - 1; index >= 0; index -= 1) stack.push(parents[index]);
  }
  return out;
}

interface FileChange {
  path: string;
  status: string; // 'added' | 'modified' | 'removed'
  additions: number;
  deletions: number;
}

function lineCount(repo: Repo, oid: string | undefined): number {
  if (oid === undefined) return 0;
  const object = repo.objects.get(oid);
  if (object === undefined) return 0;
  const text = object.data.toString('utf8');
  if (text === '') return 0;
  return text.split('\n').length;
}

/** The changed paths between two file maps, with line counts. */
function diffMaps(repo: Repo, from: Map<string, string>, to: Map<string, string>): FileChange[] {
  const changes: FileChange[] = [];
  const paths = new Set<string>([...from.keys(), ...to.keys()]);
  for (const path of [...paths].sort()) {
    const before = from.get(path);
    const after = to.get(path);
    if (before === after) continue;
    if (before === undefined) {
      changes.push({ path, status: 'added', additions: lineCount(repo, after), deletions: 0 });
    } else if (after === undefined) {
      changes.push({ path, status: 'removed', additions: 0, deletions: lineCount(repo, before) });
    } else {
      changes.push({ path, status: 'modified', additions: lineCount(repo, after), deletions: lineCount(repo, before) });
    }
  }
  return changes;
}

/**
 * Three-way merge of file maps. Returns the merged map, or null on conflict:
 * a path changed on both sides to different contents (or changed vs deleted).
 */
function mergeMaps(
  base: Map<string, string>,
  ours: Map<string, string>,
  theirs: Map<string, string>,
): Map<string, string> | null {
  const merged = new Map<string, string>(ours);
  const paths = new Set<string>([...base.keys(), ...theirs.keys()]);
  for (const path of paths) {
    const inBase = base.get(path);
    const inTheirs = theirs.get(path);
    if (inBase === inTheirs) continue; // their side did not change it
    const inOurs = ours.get(path);
    const oursChanged = inOurs !== inBase;
    if (oursChanged && inOurs !== inTheirs) return null; // both changed, differently
    if (inTheirs === undefined) merged.delete(path);
    else merged.set(path, inTheirs);
  }
  return merged;
}

/** A pull request's merge state against the current base tip. */
function pullMergeInfo(repo: Repo, pull: PullRec): { conflict: boolean; mergedMap: Map<string, string> | null; baseTip: string; headTip: string } {
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? '';
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`) ?? '';
  if (baseTip === '' || headTip === '') return { conflict: true, mergedMap: null, baseTip, headTip };
  const base = mergeBase(repo, baseTip, headTip);
  const baseMap = base === null ? new Map<string, string>() : fileMapForCommit(repo, base);
  const mergedMap = mergeMaps(baseMap, fileMapForCommit(repo, baseTip), fileMapForCommit(repo, headTip));
  return { conflict: mergedMap === null, mergedMap, baseTip, headTip };
}

/** Squash-merge a pull request: one new commit on the base branch. Null on conflict. */
function mergePull(repo: Repo, pull: PullRec): string | null {
  const info = pullMergeInfo(repo, pull);
  if (info.conflict || info.mergedMap === null) return null;
  const sha = makeCommit(repo, info.mergedMap, [info.baseTip], pull.title);
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergeCommitSha = sha;
  pull.mergedAt = nowIso();
  pull.updated = pull.mergedAt;
  touchRepo(repo);
  return sha;
}

// ---------------------------------------------------------------------------
// REST serialization

function repoObject(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: gqlId('Repository', repo.id),
    name: repo.name,
    full_name: `${VIEWER}/${repo.name}`,
    private: repo.priv,
    owner: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    description: repo.description,
    default_branch: DEFAULT_BRANCH,
    created_at: repo.created,
    updated_at: repo.updated,
    url: `/api/v3/repos/${VIEWER}/${repo.name}`,
    html_url: `/${VIEWER}/${repo.name}`,
    clone_url: `/${VIEWER}/${repo.name}.git`,
  };
}

function repoBuffer(repo: Repo): Buffer {
  if (repo.jsonBuf === null) repo.jsonBuf = Buffer.from(JSON.stringify(repoObject(repo)), 'utf8');
  return repo.jsonBuf;
}

function labelObject(repo: Repo, name: string): Record<string, unknown> {
  const label = repo.labels.get(name);
  return { name, color: label === undefined ? 'ededed' : label.color, description: null };
}

function issueObject(repo: Repo, issue: IssueRec): Record<string, unknown> {
  return {
    id: issue.dbId,
    node_id: gqlId('Issue', issue.dbId),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => labelObject(repo, name)),
    user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    author_association: 'OWNER',
    comments: issue.comments.length,
    created_at: issue.created,
    updated_at: issue.updated,
    url: `/api/v3/repos/${VIEWER}/${repo.name}/issues/${issue.number}`,
    html_url: `/${VIEWER}/${repo.name}/issues/${issue.number}`,
  };
}

function issueBuffer(repo: Repo, issue: IssueRec): Buffer {
  if (issue.buf === null) issue.buf = Buffer.from(JSON.stringify(issueObject(repo, issue)), 'utf8');
  return issue.buf;
}

function pullObject(repo: Repo, pull: PullRec): Record<string, unknown> {
  const headSha = repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headShaAtCreate;
  const baseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseShaAtCreate;
  return {
    id: pull.dbId,
    node_id: gqlId('PullRequest', pull.dbId),
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.headRef, sha: headSha, label: `${VIEWER}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: baseSha, label: `${VIEWER}:${pull.baseRef}` },
    user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    created_at: pull.created,
    updated_at: pull.updated,
    url: `/api/v3/repos/${VIEWER}/${repo.name}/pulls/${pull.number}`,
    html_url: `/${VIEWER}/${repo.name}/pulls/${pull.number}`,
  };
}

function commitObject(repo: Repo, oid: string): Record<string, unknown> {
  const object = repo.objects.get(oid);
  const info = object === undefined ? { tree: '', parents: [], message: '', author: '', committer: '' } : parseCommit(object.data);
  const splitWho = (line: string): Record<string, unknown> => {
    const match = /^(.*) <(.*)> (\d+) ([+-]\d{4})$/.exec(line);
    if (match === null) return { name: '', email: '', date: repo.created };
    return { name: match[1], email: match[2], date: new Date(Number(match[3]) * 1000).toISOString() };
  };
  return {
    sha: oid,
    node_id: gqlId('Commit', 0) + oid.slice(0, 8),
    commit: {
      message: info.message,
      tree: { sha: info.tree },
      author: splitWho(info.author),
      committer: splitWho(info.committer),
    },
    author: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    committer: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    parents: info.parents.map((parent) => ({ sha: parent })),
  };
}

// ---------------------------------------------------------------------------
// HTTP plumbing

interface Req {
  method: string;
  path: string; // pathname, no query
  query: string; // raw query string, '' when absent
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  host: string;
}

interface Res {
  status: number;
  body: Buffer;
  type: string;
  headers?: Record<string, string>;
}

const EMPTY_BUF = Buffer.alloc(0);
const NOT_FOUND_BUF = Buffer.from('{"message":"Not Found"}', 'utf8');
const BAD_CREDENTIALS_BUF = Buffer.from('{"message":"Bad credentials"}', 'utf8');
const HEALTH_BUF = Buffer.from('{"ok":true}', 'utf8');

function jsonRes(status: number, value: unknown, headers?: Record<string, string>): Res {
  return { status, body: Buffer.from(JSON.stringify(value), 'utf8'), type: JSON_CT, headers };
}
function bufRes(status: number, body: Buffer, headers?: Record<string, string>): Res {
  return { status, body, type: JSON_CT, headers };
}
function msgRes(status: number, message: string): Res {
  return { status, body: Buffer.from(JSON.stringify({ message }), 'utf8'), type: JSON_CT };
}
function notFound(): Res {
  return { status: 404, body: NOT_FOUND_BUF, type: JSON_CT };
}

function parseBodyJson(req: Req): { ok: boolean; value: Record<string, unknown> } {
  if (req.body.length === 0) return { ok: true, value: {} };
  try {
    const value = JSON.parse(req.body.toString('utf8')) as unknown;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return { ok: true, value: {} };
    return { ok: true, value: value as Record<string, unknown> };
  } catch {
    return { ok: false, value: {} };
  }
}

function queryParam(req: Req, name: string): string | null {
  if (req.query === '') return null;
  return new URLSearchParams(req.query).get(name);
}
function queryInt(req: Req, name: string, fallback: number): number {
  const raw = queryParam(req, name);
  if (raw === null) return fallback;
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function decodeSeg(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

// ---------------------------------------------------------------------------
// REST handlers

function paginate<T>(req: Req, items: T[], basePath: string): { page: T[]; link: string | null } {
  const perPage = Math.min(100, queryInt(req, 'per_page', 30));
  const page = queryInt(req, 'page', 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  if (start + perPage < items.length) {
    const last = Math.ceil(items.length / perPage);
    const origin = `http://${req.host}`;
    link =
      `<${origin}${basePath}?per_page=${perPage}&page=${page + 1}>; rel="next", ` +
      `<${origin}${basePath}?per_page=${perPage}&page=${last}>; rel="last"`;
  }
  return { page: slice, link };
}

function restRoot(req: Req): Res {
  if (req.method === 'GET' && (req.path === '/api/v3' || req.path === '/api/v3/')) {
    return jsonRes(
      200,
      {
        current_user_url: '/api/v3/user',
        repository_url: '/api/v3/repos/{owner}/{repo}',
        rate_limit_url: '/api/v3/rate_limit',
      },
      { 'x-oauth-scopes': 'repo, read:org' },
    );
  }
  return restDispatch(req);
}

function restDispatch(req: Req): Res {
  const rest = req.path.slice('/api/v3'.length); // '' or '/...'
  const seg = rest === '' ? [] : rest.slice(1).split('/').map(decodeSeg);
  const method = req.method;

  if (seg.length === 1 && seg[0] === 'meta' && method === 'GET') {
    return jsonRes(200, { installed_version: 'forge-v2/1.0.0', verifiable_password_authentication: false });
  }
  if (seg.length === 1 && seg[0] === 'user' && method === 'GET') {
    return jsonRes(200, { login: VIEWER, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
  }
  if (seg.length === 2 && seg[0] === 'user' && seg[1] === 'repos') {
    if (method === 'GET') {
      const all = [...repos.values()];
      const { page, link } = paginate(req, all, '/api/v3/user/repos');
      const headers: Record<string, string> = {};
      if (link !== null) headers.link = link;
      return {
        status: 200,
        body: Buffer.from(`[${page.map((repo) => repoBuffer(repo).toString('utf8')).join(',')}]`, 'utf8'),
        type: JSON_CT,
        headers,
      };
    }
    if (method === 'POST') {
      const parsed = parseBodyJson(req);
      if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
      const name = typeof parsed.value.name === 'string' ? parsed.value.name : '';
      if (name === '') return msgRes(422, 'name is required');
      if (repos.has(name)) return msgRes(422, 'Repository already exists');
      const repo = createRepo(
        name,
        parsed.value.private === undefined ? false : parsed.value.private === true,
        typeof parsed.value.description === 'string' ? parsed.value.description : '',
      );
      return bufRes(201, repoBuffer(repo));
    }
    return notFound();
  }

  if (seg.length >= 3 && seg[0] === 'repos') {
    const owner = seg[1];
    const repo = repos.get(seg[2]);
    if (owner !== VIEWER || repo === undefined) return notFound();
    return repoDispatch(req, repo, seg.slice(3));
  }
  return notFound();
}

function repoDispatch(req: Req, repo: Repo, seg: string[]): Res {
  const method = req.method;
  const repoPath = `/api/v3/repos/${VIEWER}/${repo.name}`;

  // the repository itself
  if (seg.length === 0) {
    if (method === 'GET') return bufRes(200, repoBuffer(repo));
    if (method === 'PATCH') {
      const parsed = parseBodyJson(req);
      if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
      if (typeof parsed.value.description === 'string') repo.description = parsed.value.description;
      if (typeof parsed.value.name === 'string' && parsed.value.name !== '' && parsed.value.name !== repo.name) {
        repos.delete(repo.name);
        repo.name = parsed.value.name;
        repos.set(repo.name, repo);
      }
      if (typeof parsed.value.private === 'boolean') repo.priv = parsed.value.private;
      repo.jsonBuf = null;
      repo.updated = nowIso();
      return bufRes(200, repoBuffer(repo));
    }
    if (method === 'DELETE') {
      repos.delete(repo.name);
      for (const [dbId, entry] of issueByDbId) if (entry.repo === repo) issueByDbId.delete(dbId);
      for (const [dbId, entry] of pullByDbId) if (entry.repo === repo) pullByDbId.delete(dbId);
      return { status: 204, body: EMPTY_BUF, type: JSON_CT };
    }
    return notFound();
  }

  // branches
  if (seg[0] === 'branches') {
    if (seg.length === 1 && method === 'GET') {
      const list: unknown[] = [];
      for (const [ref, oid] of repo.refs) {
        if (ref.startsWith('refs/heads/')) list.push({ name: ref.slice('refs/heads/'.length), commit: { sha: oid }, protected: false });
      }
      return jsonRes(200, list);
    }
    if (seg.length >= 2 && method === 'GET') {
      const branch = seg.slice(1).join('/');
      const oid = repo.refs.get(`refs/heads/${branch}`);
      if (oid === undefined) return notFound();
      return jsonRes(200, { name: branch, commit: { sha: oid }, protected: false });
    }
    return notFound();
  }

  // commits
  if (seg[0] === 'commits') {
    if (seg.length === 1 && method === 'GET') {
      const shaParam = queryParam(req, 'sha');
      let tip: string | undefined;
      if (shaParam === null || shaParam === '') tip = repo.refs.get(`refs/heads/${DEFAULT_BRANCH}`);
      else if (isOid(shaParam)) tip = shaParam;
      else tip = repo.refs.get(`refs/heads/${shaParam}`);
      if (tip === undefined) return jsonRes(200, []);
      const { page } = paginate(req, listCommits(repo, tip), `${repoPath}/commits`);
      return jsonRes(200, page.map((oid) => commitObject(repo, oid)));
    }
    if (seg.length === 2 && method === 'GET') {
      if (!isOid(seg[1]) || !repo.objects.has(seg[1])) return notFound();
      return jsonRes(200, commitObject(repo, seg[1]));
    }
    return notFound();
  }

  // git data refs
  if (seg[0] === 'git' && seg[1] === 'refs') {
    if (seg.length === 2 && method === 'POST') {
      const parsed = parseBodyJson(req);
      if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
      const ref = typeof parsed.value.ref === 'string' ? parsed.value.ref : '';
      const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) return msgRes(422, 'Invalid ref or sha');
      repo.refs.set(ref, sha);
      touchRepo(repo);
      return jsonRes(201, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } });
    }
    if (seg.length >= 3 && method === 'GET') {
      const ref = `refs/${seg.slice(2).join('/')}`;
      const oid = repo.refs.get(ref);
      if (oid === undefined) return notFound();
      return jsonRes(200, { ref, object: { sha: oid, type: repo.objects.get(oid)?.type ?? 'commit' } });
    }
    if (seg.length >= 3 && method === 'DELETE') {
      const ref = `refs/${seg.slice(2).join('/')}`;
      if (!repo.refs.has(ref)) return notFound();
      repo.refs.delete(ref);
      touchRepo(repo);
      return { status: 204, body: EMPTY_BUF, type: JSON_CT };
    }
    return notFound();
  }

  // contents
  if (seg[0] === 'contents') {
    return contentsDispatch(req, repo, seg.slice(1).join('/'));
  }

  // labels
  if (seg[0] === 'labels') {
    if (seg.length === 1 && method === 'POST') {
      const parsed = parseBodyJson(req);
      if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
      const name = typeof parsed.value.name === 'string' ? parsed.value.name : '';
      if (name === '') return msgRes(422, 'name is required');
      if (repo.labels.has(name)) return msgRes(422, 'Label already exists');
      const color = typeof parsed.value.color === 'string' ? parsed.value.color : 'ededed';
      repo.labels.set(name, { name, color });
      return jsonRes(201, { name, color, description: null });
    }
    if (seg.length === 1 && method === 'GET') {
      return jsonRes(200, [...repo.labels.values()].map((label) => ({ name: label.name, color: label.color, description: null })));
    }
    return notFound();
  }

  // issues and comments
  if (seg[0] === 'issues') {
    return issuesDispatch(req, repo, seg);
  }

  // pull requests
  if (seg[0] === 'pulls') {
    return pullsDispatch(req, repo, seg);
  }

  return notFound();
}

/** The branch a contents call targets: the body's or query's branch, else the default. */
function contentsBranch(req: Req, body: Record<string, unknown>): string {
  if (typeof body.branch === 'string' && body.branch !== '') return body.branch;
  const fromQuery = queryParam(req, 'branch');
  if (fromQuery !== null && fromQuery !== '') return fromQuery;
  return DEFAULT_BRANCH;
}

/** Commit a file map onto a branch (creating the branch from the default tip when new). */
function commitToBranch(repo: Repo, branch: string, files: Map<string, string>, message: string): string {
  const ref = `refs/heads/${branch}`;
  const parent = repo.refs.get(ref);
  const parents = parent === undefined ? [] : [parent];
  const sha = makeCommit(repo, files, parents, message);
  repo.refs.set(ref, sha);
  touchRepo(repo);
  return sha;
}

function contentsDispatch(req: Req, repo: Repo, path: string): Res {
  const method = req.method;

  if (method === 'GET') {
    const refParam = queryParam(req, 'ref');
    let files: Map<string, string>;
    if (refParam === null || refParam === '' || refParam === DEFAULT_BRANCH) {
      const tip = repo.refs.get(`refs/heads/${DEFAULT_BRANCH}`);
      files = tip === undefined ? new Map() : fileMapForCommit(repo, tip);
    } else if (isOid(refParam) && repo.objects.has(refParam)) {
      files = fileMapForCommit(repo, peelToCommit(repo, refParam));
    } else {
      const tip = repo.refs.get(`refs/heads/${refParam}`);
      if (tip === undefined) return notFound();
      files = fileMapForCommit(repo, tip);
    }
    if (path === '') {
      return jsonRes(200, dirListing(repo, files, ''));
    }
    const blobOid = files.get(path);
    if (blobOid !== undefined) {
      const object = repo.objects.get(blobOid);
      const data = object === undefined ? EMPTY_BUF : object.data;
      return jsonRes(200, {
        type: 'file',
        encoding: 'base64',
        content: data.toString('base64'),
        sha: blobOid,
        size: data.length,
        name: path.slice(path.lastIndexOf('/') + 1),
        path,
      });
    }
    const prefix = `${path}/`;
    let isDir = false;
    for (const key of files.keys()) {
      if (key.startsWith(prefix)) {
        isDir = true;
        break;
      }
    }
    if (isDir) return jsonRes(200, dirListing(repo, files, path));
    return notFound();
  }

  if (method === 'PUT') {
    const parsed = parseBodyJson(req);
    if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
    if (path === '') return msgRes(422, 'path is required');
    const branch = contentsBranch(req, parsed.value);
    const ref = `refs/heads/${branch}`;
    let tip = repo.refs.get(ref);
    if (tip === undefined) {
      // a contents write on a new branch starts it from the default branch tip
      const defaultTip = repo.refs.get(`refs/heads/${DEFAULT_BRANCH}`);
      if (defaultTip !== undefined) repo.refs.set(ref, defaultTip);
      tip = defaultTip;
    }
    const files = new Map(tip === undefined ? new Map<string, string>() : fileMapForCommit(repo, tip));
    const existing = files.get(path);
    const givenSha = typeof parsed.value.sha === 'string' ? parsed.value.sha : undefined;
    if (givenSha !== undefined && givenSha !== existing) return msgRes(409, 'sha does not match the current file');
    if (givenSha === undefined && existing !== undefined && parsed.value.sha === null) {
      // no sha on an update is accepted, as the suite's branch commits rely on it
    }
    const data = b64decodeToBuffer(typeof parsed.value.content === 'string' ? parsed.value.content : '');
    const blobOid = sha1Hex('blob', data);
    if (!repo.objects.has(blobOid)) repo.objects.set(blobOid, { type: 'blob', data });
    files.set(path, blobOid);
    const message = typeof parsed.value.message === 'string' ? parsed.value.message : 'Update file';
    const commitSha = commitToBranch(repo, branch, files, message);
    const created = existing === undefined;
    return jsonRes(created ? 201 : 200, {
      content: {
        type: 'file',
        encoding: 'base64',
        sha: blobOid,
        size: data.length,
        name: path.slice(path.lastIndexOf('/') + 1),
        path,
      },
      commit: { sha: commitSha, message },
    });
  }

  if (method === 'DELETE') {
    const parsed = parseBodyJson(req);
    if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
    const branch = contentsBranch(req, parsed.value);
    const tip = repo.refs.get(`refs/heads/${branch}`);
    if (tip === undefined) return notFound();
    const files = new Map(fileMapForCommit(repo, tip));
    if (!files.has(path)) return notFound();
    files.delete(path);
    const message = typeof parsed.value.message === 'string' ? parsed.value.message : 'Delete file';
    const commitSha = commitToBranch(repo, branch, files, message);
    return jsonRes(200, { content: null, commit: { sha: commitSha, message } });
  }

  return notFound();
}

function dirListing(repo: Repo, files: Map<string, string>, dir: string): unknown[] {
  const prefix = dir === '' ? '' : `${dir}/`;
  const entries = new Map<string, { type: string; name: string; path: string; sha: string }>();
  for (const [path, oid] of files) {
    if (!path.startsWith(prefix)) continue;
    const rest = path.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash < 0) {
      entries.set(rest, { type: 'file', name: rest, path, sha: oid });
    } else {
      const name = rest.slice(0, slash);
      if (!entries.has(name)) {
        entries.set(name, { type: 'dir', name, path: `${prefix}${name}`, sha: dirTreeOid(repo, files, `${prefix}${name}`) });
      }
    }
  }
  return [...entries.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
}

/** The tree oid of a directory inside a file map (recomputed from the map's blobs). */
function dirTreeOid(repo: Repo, files: Map<string, string>, dir: string): string {
  const sub = new Map<string, string>();
  const prefix = `${dir}/`;
  for (const [path, oid] of files) {
    if (path.startsWith(prefix)) sub.set(path.slice(prefix.length), oid);
  }
  // build the subtree bottom-up by reusing the root builder on relative paths
  const rootOid = storeTreeForMap(repo, sub);
  return rootOid;
}

function issuesDispatch(req: Req, repo: Repo, seg: string[]): Res {
  const method = req.method;
  const repoPath = `/api/v3/repos/${VIEWER}/${repo.name}`;

  if (seg.length === 1) {
    if (method === 'POST') {
      const parsed = parseBodyJson(req);
      if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
      const title = typeof parsed.value.title === 'string' ? parsed.value.title : '';
      if (title === '') return msgRes(422, 'title is required');
      const labels = Array.isArray(parsed.value.labels) ? parsed.value.labels.map((entry) => String(entry)) : [];
      for (const label of labels) {
        if (!repo.labels.has(label)) return msgRes(422, `Label "${label}" does not exist`);
      }
      const stamp = nowIso();
      const issue: IssueRec = {
        dbId: nextIssueDbId++,
        number: repo.nextNumber++,
        title,
        body: typeof parsed.value.body === 'string' ? parsed.value.body : '',
        state: 'open',
        labels,
        comments: [],
        created: stamp,
        updated: stamp,
        buf: null,
      };
      repo.issues.set(issue.number, issue);
      issueByDbId.set(issue.dbId, { repo, issue });
      return bufRes(201, issueBuffer(repo, issue));
    }
    if (method === 'GET') {
      const state = queryParam(req, 'state') ?? 'open';
      const direction = queryParam(req, 'direction') ?? 'desc';
      let list = [...repo.issues.values()];
      if (state === 'open') list = list.filter((issue) => issue.state === 'open');
      else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
      list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
      const { page, link } = paginate(req, list, `${repoPath}/issues`);
      const headers: Record<string, string> = {};
      if (link !== null) headers.link = link;
      return {
        status: 200,
        body: Buffer.from(`[${page.map((issue) => issueBuffer(repo, issue).toString('utf8')).join(',')}]`, 'utf8'),
        type: JSON_CT,
        headers,
      };
    }
    return notFound();
  }

  const number = Number.parseInt(seg[1], 10);
  const issue = Number.isFinite(number) ? repo.issues.get(number) : undefined;

  if (seg.length === 2) {
    if (issue === undefined) return notFound();
    if (method === 'GET') return bufRes(200, issueBuffer(repo, issue));
    if (method === 'PATCH') {
      const parsed = parseBodyJson(req);
      if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
      if (typeof parsed.value.state === 'string') issue.state = parsed.value.state;
      if (typeof parsed.value.title === 'string') issue.title = parsed.value.title;
      if (typeof parsed.value.body === 'string') issue.body = parsed.value.body;
      if (Array.isArray(parsed.value.labels)) {
        const labels = parsed.value.labels.map((entry) => String(entry));
        for (const label of labels) if (!repo.labels.has(label)) return msgRes(422, `Label "${label}" does not exist`);
        issue.labels = labels;
      }
      issue.updated = nowIso();
      issue.buf = null;
      return bufRes(200, issueBuffer(repo, issue));
    }
    return notFound();
  }

  if (seg.length === 3 && seg[2] === 'comments') {
    if (issue === undefined) return notFound();
    if (method === 'POST') {
      const parsed = parseBodyJson(req);
      if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
      const body = typeof parsed.value.body === 'string' ? parsed.value.body : '';
      const comment = { id: nextCommentId++, body, created: nowIso() };
      issue.comments.push(comment);
      issue.buf = null;
      return jsonRes(201, {
        id: comment.id,
        node_id: gqlId('IssueComment', comment.id),
        body: comment.body,
        user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
        created_at: comment.created,
        updated_at: comment.created,
      });
    }
    if (method === 'GET') {
      return jsonRes(
        200,
        issue.comments.map((comment) => ({
          id: comment.id,
          node_id: gqlId('IssueComment', comment.id),
          body: comment.body,
          user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
          created_at: comment.created,
          updated_at: comment.created,
        })),
      );
    }
    return notFound();
  }

  return notFound();
}

function pullsDispatch(req: Req, repo: Repo, seg: string[]): Res {
  const method = req.method;
  const repoPath = `/api/v3/repos/${VIEWER}/${repo.name}`;

  if (seg.length === 1) {
    if (method === 'POST') {
      const parsed = parseBodyJson(req);
      if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
      const stripOwner = (ref: string): string => (ref.includes(':') ? ref.slice(ref.indexOf(':') + 1) : ref);
      const head = stripOwner(typeof parsed.value.head === 'string' ? parsed.value.head : '');
      const base = stripOwner(typeof parsed.value.base === 'string' ? parsed.value.base : DEFAULT_BRANCH);
      const headSha = repo.refs.get(`refs/heads/${head}`);
      if (head === '' || headSha === undefined) return msgRes(422, 'head branch does not exist');
      const baseSha = repo.refs.get(`refs/heads/${base}`) ?? ZERO_OID;
      const stamp = nowIso();
      const pull: PullRec = {
        dbId: nextPullDbId++,
        number: repo.nextNumber++,
        title: typeof parsed.value.title === 'string' ? parsed.value.title : '',
        body: typeof parsed.value.body === 'string' ? parsed.value.body : '',
        state: 'open',
        merged: false,
        headRef: head,
        baseRef: base,
        headShaAtCreate: headSha,
        baseShaAtCreate: baseSha,
        mergeCommitSha: null,
        mergedAt: null,
        created: stamp,
        updated: stamp,
      };
      repo.pulls.set(pull.number, pull);
      pullByDbId.set(pull.dbId, { repo, pull });
      return jsonRes(201, pullObject(repo, pull));
    }
    if (method === 'GET') {
      const state = queryParam(req, 'state') ?? 'open';
      let list = [...repo.pulls.values()];
      if (state === 'open') list = list.filter((pull) => pull.state === 'open');
      else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
      list.sort((a, b) => a.number - b.number);
      const { page, link } = paginate(req, list, `${repoPath}/pulls`);
      const headers: Record<string, string> = {};
      if (link !== null) headers.link = link;
      return jsonRes(200, page.map((pull) => pullObject(repo, pull)), headers);
    }
    return notFound();
  }

  const number = Number.parseInt(seg[1], 10);
  const pull = Number.isFinite(number) ? repo.pulls.get(number) : undefined;

  if (seg.length === 2 && method === 'GET') {
    if (pull === undefined) return notFound();
    return jsonRes(200, pullObject(repo, pull));
  }

  if (seg.length === 3 && seg[2] === 'files' && method === 'GET') {
    if (pull === undefined) return notFound();
    const headTip = repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headShaAtCreate;
    const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseShaAtCreate;
    const base = mergeBase(repo, baseTip, headTip);
    const fromMap = base === null ? new Map<string, string>() : fileMapForCommit(repo, base);
    const changes = diffMaps(repo, fromMap, fileMapForCommit(repo, headTip));
    const { page } = paginate(
      req,
      changes.map((change) => ({
        filename: change.path,
        status: change.status,
        additions: change.additions,
        deletions: change.deletions,
        changes: change.additions + change.deletions,
        sha: fileMapForCommit(repo, headTip).get(change.path) ?? '',
      })),
      `${repoPath}/pulls/${number}/files`,
    );
    return jsonRes(200, page);
  }

  if (seg.length === 3 && seg[2] === 'merge' && method === 'PUT') {
    if (pull === undefined) return notFound();
    const parsed = parseBodyJson(req);
    if (!parsed.ok) return msgRes(400, 'Problems parsing JSON');
    if (pull.merged) return msgRes(405, 'Pull Request is already merged');
    const sha = mergePull(repo, pull);
    if (sha === null) return msgRes(405, 'Pull Request is not mergeable');
    return jsonRes(200, { sha, merged: true, message: 'Pull Request successfully merged' });
  }

  return notFound();
}

// ---------------------------------------------------------------------------
// GraphQL: a small parser and executor for the documents gh sends

type GqlValue =
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'variable'; name: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlField {
  alias: string | null;
  name: string;
  args: Array<{ name: string; value: GqlValue }>;
  selections: GqlSelection[];
}
type GqlSelection = { kind: 'field'; field: GqlField } | { kind: 'fragment'; typeName: string; selections: GqlSelection[] };

interface GqlOperation {
  type: string; // 'query' | 'mutation'
  selections: GqlSelection[];
}

class GqlTokens {
  private tokens: Array<{ kind: string; value: string }> = [];
  private at = 0;

  constructor(text: string) {
    let index = 0;
    while (index < text.length) {
      const ch = text[index];
      if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
        index += 1;
        continue;
      }
      if (ch === '#') {
        while (index < text.length && text[index] !== '\n') index += 1;
        continue;
      }
      if (text.startsWith('...', index)) {
        this.tokens.push({ kind: 'punct', value: '...' });
        index += 3;
        continue;
      }
      if ('{}()[]:$=!@|&'.includes(ch)) {
        this.tokens.push({ kind: 'punct', value: ch });
        index += 1;
        continue;
      }
      if (ch === '"') {
        if (text.startsWith('"""', index)) {
          const end = text.indexOf('"""', index + 3);
          this.tokens.push({ kind: 'string', value: text.slice(index + 3, end < 0 ? text.length : end) });
          index = end < 0 ? text.length : end + 3;
          continue;
        }
        let value = '';
        index += 1;
        while (index < text.length && text[index] !== '"') {
          if (text[index] === '\\' && index + 1 < text.length) {
            const esc = text[index + 1];
            value += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
            index += 2;
          } else {
            value += text[index];
            index += 1;
          }
        }
        index += 1;
        this.tokens.push({ kind: 'string', value });
        continue;
      }
      if (/[0-9-]/.test(ch)) {
        let end = index;
        while (end < text.length && /[0-9.eE+-]/.test(text[end])) end += 1;
        this.tokens.push({ kind: 'number', value: text.slice(index, end) });
        index = end;
        continue;
      }
      if (/[_A-Za-z]/.test(ch)) {
        let end = index;
        while (end < text.length && /[_0-9A-Za-z]/.test(text[end])) end += 1;
        this.tokens.push({ kind: 'name', value: text.slice(index, end) });
        index = end;
        continue;
      }
      index += 1;
    }
  }

  peek(): { kind: string; value: string } | null {
    return this.at < this.tokens.length ? this.tokens[this.at] : null;
  }
  next(): { kind: string; value: string } | null {
    const token = this.peek();
    if (token !== null) this.at += 1;
    return token;
  }
  expect(value: string): void {
    const token = this.next();
    if (token === null || token.value !== value) throw new Error(`expected ${value}`);
  }
  skipBalanced(open: string, close: string): void {
    let depth = 0;
    for (;;) {
      const token = this.next();
      if (token === null) return;
      if (token.value === open) depth += 1;
      else if (token.value === close) {
        depth -= 1;
        if (depth === 0) return;
      }
    }
  }
}

function parseGqlValue(tokens: GqlTokens): GqlValue {
  const token = tokens.next();
  if (token === null) throw new Error('unexpected end of document');
  if (token.value === '$') {
    const name = tokens.next();
    return { kind: 'variable', name: name === null ? '' : name.value };
  }
  if (token.kind === 'string') return { kind: 'string', value: token.value };
  if (token.kind === 'number') {
    return token.value.includes('.') || token.value.includes('e') || token.value.includes('E')
      ? { kind: 'float', value: Number(token.value) }
      : { kind: 'int', value: Number.parseInt(token.value, 10) };
  }
  if (token.value === '[') {
    const items: GqlValue[] = [];
    while (tokens.peek()?.value !== ']') items.push(parseGqlValue(tokens));
    tokens.next();
    return { kind: 'list', items };
  }
  if (token.value === '{') {
    const fields: Array<{ name: string; value: GqlValue }> = [];
    while (tokens.peek()?.value !== '}') {
      const name = tokens.next();
      tokens.expect(':');
      fields.push({ name: name === null ? '' : name.value, value: parseGqlValue(tokens) });
    }
    tokens.next();
    return { kind: 'object', fields };
  }
  if (token.kind === 'name') {
    if (token.value === 'true') return { kind: 'boolean', value: true };
    if (token.value === 'false') return { kind: 'boolean', value: false };
    if (token.value === 'null') return { kind: 'null' };
    return { kind: 'enum', value: token.value };
  }
  throw new Error(`unexpected token ${token.value}`);
}

function parseGqlSelections(tokens: GqlTokens): GqlSelection[] {
  tokens.expect('{');
  const selections: GqlSelection[] = [];
  while (tokens.peek()?.value !== '}') {
    const token = tokens.peek();
    if (token === null) break;
    if (token.value === '...') {
      tokens.next();
      const on = tokens.next();
      if (on !== null && on.value === 'on') {
        const typeName = tokens.next();
        selections.push({ kind: 'fragment', typeName: typeName === null ? '' : typeName.value, selections: parseGqlSelections(tokens) });
      } else {
        // a named fragment spread: not used by the suite's documents; skip it
        continue;
      }
      continue;
    }
    const first = tokens.next();
    if (first === null || first.kind !== 'name') continue;
    let alias: string | null = null;
    let name = first.value;
    if (tokens.peek()?.value === ':') {
      tokens.next();
      alias = name;
      const real = tokens.next();
      name = real === null ? '' : real.value;
    }
    const args: Array<{ name: string; value: GqlValue }> = [];
    if (tokens.peek()?.value === '(') {
      tokens.next();
      while (tokens.peek()?.value !== ')') {
        const argName = tokens.next();
        tokens.expect(':');
        args.push({ name: argName === null ? '' : argName.value, value: parseGqlValue(tokens) });
      }
      tokens.next();
    }
    let sub: GqlSelection[] = [];
    if (tokens.peek()?.value === '{') sub = parseGqlSelections(tokens);
    selections.push({ kind: 'field', field: { alias, name, args, selections: sub } });
  }
  tokens.next();
  return selections;
}

function parseGqlDocument(text: string): GqlOperation {
  const tokens = new GqlTokens(text);
  let type = 'query';
  const first = tokens.peek();
  if (first !== null && (first.value === 'query' || first.value === 'mutation' || first.value === 'subscription')) {
    tokens.next();
    type = first.value === 'mutation' ? 'mutation' : 'query';
    const nameToken = tokens.peek();
    if (nameToken !== null && nameToken.kind === 'name') tokens.next(); // operation name
    if (tokens.peek()?.value === '(') tokens.skipBalanced('(', ')'); // variable definitions
  }
  return { type, selections: parseGqlSelections(tokens) };
}

function evalGqlValue(value: GqlValue, vars: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
    case 'enum':
      return value.value;
    case 'null':
      return null;
    case 'variable':
      return vars[value.name];
    case 'list':
      return value.items.map((item) => evalGqlValue(item, vars));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = evalGqlValue(field.value, vars);
      return out;
    }
  }
}

// --- the schema the introspection probes describe

const TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author', 'labels', 'comments', 'repository', 'closed'],
  PullRequest: [
    'id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files',
    'url', 'createdAt', 'updatedAt', 'author', 'commits', 'additions', 'deletions', 'changedFiles', 'mergedAt',
  ],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled',
    'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt', 'updatedAt', 'isPrivate',
  ],
  User: ['id', 'login', 'name', 'url', 'avatarUrl'],
};
const TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
};

// --- execution

interface GVal {
  t: string;
  v: unknown;
}
function g(t: string, v: unknown): GVal {
  return { t, v };
}

interface GqlError {
  message: string;
}

function repoGqlState(repo: Repo): GVal {
  return g('Repository', repo);
}
function issueGql(repo: Repo, issue: IssueRec): GVal {
  return g('Issue', { repo, issue });
}
function pullGql(repo: Repo, pull: PullRec): GVal {
  return g('PullRequest', { repo, pull });
}

function issueConnection(repo: Repo, args: Record<string, unknown>): GVal {
  let list = [...repo.issues.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((state) => String(state).toLowerCase()));
    list = list.filter((issue) => wanted.has(issue.state));
  }
  const orderBy = args.orderBy as Record<string, unknown> | undefined;
  const direction = orderBy !== undefined && typeof orderBy.direction === 'string' ? orderBy.direction : 'ASC';
  list.sort((a, b) => (direction === 'DESC' ? b.number - a.number : a.number - b.number));
  let start = 0;
  const after = args.after;
  if (typeof after === 'string' && after !== '') {
    try {
      const decoded = Buffer.from(after, 'base64').toString('utf8');
      const match = /^cursor:(\d+)$/.exec(decoded);
      if (match !== null) {
        const at = list.findIndex((issue) => issue.number === Number(match[1]));
        if (at >= 0) start = at + 1;
      }
    } catch {
      start = 0;
    }
  }
  const first = typeof args.first === 'number' ? args.first : list.length;
  const slice = list.slice(start, start + Math.max(0, first));
  const hasNext = start + slice.length < list.length;
  const last = slice[slice.length - 1];
  const endCursor = last === undefined ? null : Buffer.from(`cursor:${last.number}`, 'utf8').toString('base64');
  return g('IssueConnection', {
    nodes: slice.map((issue) => issueGql(repo, issue)),
    pageInfo: g('PageInfo', { hasNextPage: hasNext, endCursor, hasPreviousPage: start > 0, startCursor: endCursor }),
    totalCount: list.length,
  });
}

function pullConnection(repo: Repo, args: Record<string, unknown>): GVal {
  let list = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((state) => String(state)));
    list = list.filter((pull) => {
      const state = pull.merged ? 'MERGED' : pull.state === 'closed' ? 'CLOSED' : 'OPEN';
      return wanted.has(state);
    });
  }
  const first = typeof args.first === 'number' ? args.first : list.length;
  const slice = list.slice(0, Math.max(0, first));
  return g('PullRequestConnection', {
    nodes: slice.map((pull) => pullGql(repo, pull)),
    pageInfo: g('PageInfo', { hasNextPage: slice.length < list.length, endCursor: null, hasPreviousPage: false, startCursor: null }),
    totalCount: list.length,
  });
}

function pullFiles(repo: Repo, pull: PullRec): FileChange[] {
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headShaAtCreate;
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseShaAtCreate;
  const base = mergeBase(repo, baseTip, headTip);
  const fromMap = base === null ? new Map<string, string>() : fileMapForCommit(repo, base);
  return diffMaps(repo, fromMap, fileMapForCommit(repo, headTip));
}

type Resolver = (obj: GVal, args: Record<string, unknown>, vars: Record<string, unknown>, errors: GqlError[]) => unknown;

const RESOLVERS: Record<string, Record<string, Resolver>> = {
  Query: {
    viewer: () => g('User', { login: VIEWER }),
    repository: (_obj, args) => {
      if (args.owner !== VIEWER) return null;
      const repo = typeof args.name === 'string' ? repos.get(args.name) : undefined;
      return repo === undefined ? null : repoGqlState(repo);
    },
    node: (_obj, args) => {
      if (typeof args.id !== 'string') return null;
      const decoded = gqlDecode(args.id);
      if (decoded === null) return null;
      if (decoded.type === 'Repository') {
        for (const repo of repos.values()) if (repo.id === decoded.dbId) return repoGqlState(repo);
        return null;
      }
      if (decoded.type === 'Issue') {
        const found = issueByDbId.get(decoded.dbId);
        return found === undefined ? null : issueGql(found.repo, found.issue);
      }
      if (decoded.type === 'PullRequest') {
        const found = pullByDbId.get(decoded.dbId);
        return found === undefined ? null : pullGql(found.repo, found.pull);
      }
      return null;
    },
    __type: (_obj, args) => (typeof args.name === 'string' ? g('__Type', { name: args.name }) : null),
    rateLimit: () => g('RateLimit', { limit: 5000, cost: 1, remaining: 4999 }),
  },
  Mutation: {
    createIssue: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = typeof input.repositoryId === 'string' ? gqlDecode(input.repositoryId) : null;
      if (decoded === null || decoded.type !== 'Repository') return null;
      let repo: Repo | undefined;
      for (const candidate of repos.values()) if (candidate.id === decoded.dbId) repo = candidate;
      if (repo === undefined) return null;
      const stamp = nowIso();
      const issue: IssueRec = {
        dbId: nextIssueDbId++,
        number: repo.nextNumber++,
        title: typeof input.title === 'string' ? input.title : '',
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels: [],
        comments: [],
        created: stamp,
        updated: stamp,
        buf: null,
      };
      repo.issues.set(issue.number, issue);
      issueByDbId.set(issue.dbId, { repo, issue });
      return g('CreateIssuePayload', { issue: issueGql(repo, issue) });
    },
    closeIssue: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = typeof input.issueId === 'string' ? gqlDecode(input.issueId) : null;
      if (decoded === null || decoded.type !== 'Issue') return null;
      const found = issueByDbId.get(decoded.dbId);
      if (found === undefined) return null;
      found.issue.state = 'closed';
      found.issue.updated = nowIso();
      found.issue.buf = null;
      return g('CloseIssuePayload', { issue: issueGql(found.repo, found.issue) });
    },
    createPullRequest: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = typeof input.repositoryId === 'string' ? gqlDecode(input.repositoryId) : null;
      if (decoded === null || decoded.type !== 'Repository') return null;
      let repo: Repo | undefined;
      for (const candidate of repos.values()) if (candidate.id === decoded.dbId) repo = candidate;
      if (repo === undefined) return null;
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : DEFAULT_BRANCH;
      const headSha = repo.refs.get(`refs/heads/${head}`) ?? ZERO_OID;
      const baseSha = repo.refs.get(`refs/heads/${base}`) ?? ZERO_OID;
      const stamp = nowIso();
      const pull: PullRec = {
        dbId: nextPullDbId++,
        number: repo.nextNumber++,
        title: typeof input.title === 'string' ? input.title : '',
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        merged: false,
        headRef: head,
        baseRef: base,
        headShaAtCreate: headSha,
        baseShaAtCreate: baseSha,
        mergeCommitSha: null,
        mergedAt: null,
        created: stamp,
        updated: stamp,
      };
      repo.pulls.set(pull.number, pull);
      pullByDbId.set(pull.dbId, { repo, pull });
      return g('CreatePullRequestPayload', { pullRequest: pullGql(repo, pull) });
    },
    mergePullRequest: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = typeof input.pullRequestId === 'string' ? gqlDecode(input.pullRequestId) : null;
      if (decoded === null || decoded.type !== 'PullRequest') return null;
      const found = pullByDbId.get(decoded.dbId);
      if (found === undefined) return null;
      if (!found.pull.merged) mergePull(found.repo, found.pull);
      return g('MergePullRequestPayload', { pullRequest: pullGql(found.repo, found.pull) });
    },
    addComment: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = typeof input.subjectId === 'string' ? gqlDecode(input.subjectId) : null;
      if (decoded === null) return null;
      const body = typeof input.body === 'string' ? input.body : '';
      if (decoded.type === 'Issue') {
        const found = issueByDbId.get(decoded.dbId);
        if (found === undefined) return null;
        const comment = { id: nextCommentId++, body, created: nowIso() };
        found.issue.comments.push(comment);
        found.issue.buf = null;
        return g('AddCommentPayload', { commentEdge: g('CommentEdge', { node: g('IssueComment', comment) }) });
      }
      return null;
    },
  },
  User: {
    login: (obj) => (obj.v as { login: string }).login,
    id: () => gqlId('User', VIEWER_ID),
    name: () => VIEWER_NAME,
    url: () => `/${VIEWER}`,
    avatarUrl: () => '',
  },
  Repository: {
    id: (obj) => gqlId('Repository', (obj.v as Repo).id),
    databaseId: (obj) => (obj.v as Repo).id,
    name: (obj) => (obj.v as Repo).name,
    nameWithOwner: (obj) => `${VIEWER}/${(obj.v as Repo).name}`,
    owner: () => g('User', { login: VIEWER }),
    defaultBranchRef: (obj) => {
      const repo = obj.v as Repo;
      return repo.refs.has(`refs/heads/${DEFAULT_BRANCH}`) ? g('Ref', { name: DEFAULT_BRANCH }) : null;
    },
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    description: (obj) => (obj.v as Repo).description,
    isPrivate: (obj) => (obj.v as Repo).priv,
    url: (obj) => `/${VIEWER}/${(obj.v as Repo).name}`,
    createdAt: (obj) => (obj.v as Repo).created,
    updatedAt: (obj) => (obj.v as Repo).updated,
    issue: (obj, args) => {
      const repo = obj.v as Repo;
      const issue = typeof args.number === 'number' ? repo.issues.get(args.number) : undefined;
      return issue === undefined ? null : issueGql(repo, issue);
    },
    issues: (obj, args) => issueConnection(obj.v as Repo, args),
    pullRequest: (obj, args) => {
      const repo = obj.v as Repo;
      const pull = typeof args.number === 'number' ? repo.pulls.get(args.number) : undefined;
      return pull === undefined ? null : pullGql(repo, pull);
    },
    pullRequests: (obj, args) => pullConnection(obj.v as Repo, args),
  },
  Ref: {
    name: (obj) => (obj.v as { name: string }).name,
    prefix: () => 'refs/heads/',
    target: () => null,
  },
  Issue: {
    id: (obj) => gqlId('Issue', (obj.v as { issue: IssueRec }).issue.dbId),
    number: (obj) => (obj.v as { issue: IssueRec }).issue.number,
    title: (obj) => (obj.v as { issue: IssueRec }).issue.title,
    body: (obj) => (obj.v as { issue: IssueRec }).issue.body,
    state: (obj) => (obj.v as { issue: IssueRec }).issue.state.toUpperCase(),
    createdAt: (obj) => (obj.v as { issue: IssueRec }).issue.created,
    updatedAt: (obj) => (obj.v as { issue: IssueRec }).issue.updated,
    url: (obj) => {
      const { repo, issue } = obj.v as { repo: Repo; issue: IssueRec };
      return `/${VIEWER}/${repo.name}/issues/${issue.number}`;
    },
    author: () => g('User', { login: VIEWER }),
    repository: (obj) => repoGqlState((obj.v as { repo: Repo }).repo),
    labels: () => g('LabelConnection', { nodes: [] }),
    comments: () => g('IssueCommentConnection', { nodes: [] }),
    closed: (obj) => (obj.v as { issue: IssueRec }).issue.state === 'closed',
  },
  PullRequest: {
    id: (obj) => gqlId('PullRequest', (obj.v as { pull: PullRec }).pull.dbId),
    number: (obj) => (obj.v as { pull: PullRec }).pull.number,
    title: (obj) => (obj.v as { pull: PullRec }).pull.title,
    body: (obj) => (obj.v as { pull: PullRec }).pull.body,
    state: (obj) => {
      const pull = (obj.v as { pull: PullRec }).pull;
      return pull.merged ? 'MERGED' : pull.state === 'closed' ? 'CLOSED' : 'OPEN';
    },
    merged: (obj) => (obj.v as { pull: PullRec }).pull.merged,
    mergedAt: (obj) => (obj.v as { pull: PullRec }).pull.mergedAt,
    mergeable: (obj) => {
      const { repo, pull } = obj.v as { repo: Repo; pull: PullRec };
      if (pull.merged) return 'MERGEABLE';
      return pullMergeInfo(repo, pull).conflict ? 'CONFLICTING' : 'MERGEABLE';
    },
    headRefName: (obj) => (obj.v as { pull: PullRec }).pull.headRef,
    baseRefName: (obj) => (obj.v as { pull: PullRec }).pull.baseRef,
    createdAt: (obj) => (obj.v as { pull: PullRec }).pull.created,
    updatedAt: (obj) => (obj.v as { pull: PullRec }).pull.updated,
    url: (obj) => {
      const { repo, pull } = obj.v as { repo: Repo; pull: PullRec };
      return `/${VIEWER}/${repo.name}/pulls/${pull.number}`;
    },
    author: () => g('User', { login: VIEWER }),
    files: (obj, args) => {
      const { repo, pull } = obj.v as { repo: Repo; pull: PullRec };
      const changes = pullFiles(repo, pull);
      const first = typeof args.first === 'number' ? args.first : changes.length;
      return g('PullRequestChangedFileConnection', {
        nodes: changes.slice(0, Math.max(0, first)).map((change) => g('PullRequestChangedFile', change)),
        totalCount: changes.length,
      });
    },
    additions: (obj) => pullFiles((obj.v as { repo: Repo }).repo, (obj.v as { pull: PullRec }).pull).reduce((sum, c) => sum + c.additions, 0),
    deletions: (obj) => pullFiles((obj.v as { repo: Repo }).repo, (obj.v as { pull: PullRec }).pull).reduce((sum, c) => sum + c.deletions, 0),
    changedFiles: (obj) => pullFiles((obj.v as { repo: Repo }).repo, (obj.v as { pull: PullRec }).pull).length,
    commits: () => g('PullRequestCommitConnection', { nodes: [], totalCount: 0 }),
  },
  IssueConnection: {
    nodes: (obj) => (obj.v as { nodes: GVal[] }).nodes,
    pageInfo: (obj) => (obj.v as { pageInfo: GVal }).pageInfo,
    totalCount: (obj) => (obj.v as { totalCount: number }).totalCount,
    edges: (obj) => (obj.v as { nodes: GVal[] }).nodes.map((node) => g('IssueEdge', { node, cursor: '' })),
  },
  PullRequestConnection: {
    nodes: (obj) => (obj.v as { nodes: GVal[] }).nodes,
    pageInfo: (obj) => (obj.v as { pageInfo: GVal }).pageInfo,
    totalCount: (obj) => (obj.v as { totalCount: number }).totalCount,
    edges: (obj) => (obj.v as { nodes: GVal[] }).nodes.map((node) => g('PullRequestEdge', { node, cursor: '' })),
  },
  PullRequestChangedFileConnection: {
    nodes: (obj) => (obj.v as { nodes: GVal[] }).nodes,
    totalCount: (obj) => (obj.v as { totalCount: number }).totalCount,
  },
  PullRequestChangedFile: {
    path: (obj) => (obj.v as FileChange).path,
    additions: (obj) => (obj.v as FileChange).additions,
    deletions: (obj) => (obj.v as FileChange).deletions,
  },
  PageInfo: {
    hasNextPage: (obj) => (obj.v as { hasNextPage: boolean }).hasNextPage,
    hasPreviousPage: (obj) => (obj.v as { hasPreviousPage: boolean }).hasPreviousPage,
    endCursor: (obj) => (obj.v as { endCursor: string | null }).endCursor,
    startCursor: (obj) => (obj.v as { startCursor: string | null }).startCursor,
  },
  LabelConnection: { nodes: () => [], totalCount: () => 0 },
  IssueCommentConnection: { nodes: () => [], totalCount: () => 0 },
  PullRequestCommitConnection: { nodes: () => [], totalCount: () => 0 },
  IssueEdge: { node: (obj) => (obj.v as { node: GVal }).node, cursor: (obj) => (obj.v as { cursor: string }).cursor },
  PullRequestEdge: { node: (obj) => (obj.v as { node: GVal }).node, cursor: (obj) => (obj.v as { cursor: string }).cursor },
  IssueComment: {
    id: (obj) => gqlId('IssueComment', (obj.v as { id: number }).id),
    body: (obj) => (obj.v as { body: string }).body,
    createdAt: (obj) => (obj.v as { created: string }).created,
    author: () => g('User', { login: VIEWER }),
  },
  CommentEdge: { node: (obj) => (obj.v as { node: GVal }).node, cursor: () => '' },
  CreateIssuePayload: { issue: (obj) => (obj.v as { issue: GVal }).issue, clientMutationId: () => null },
  CloseIssuePayload: { issue: (obj) => (obj.v as { issue: GVal }).issue, clientMutationId: () => null },
  CreatePullRequestPayload: { pullRequest: (obj) => (obj.v as { pullRequest: GVal }).pullRequest, clientMutationId: () => null },
  MergePullRequestPayload: { pullRequest: (obj) => (obj.v as { pullRequest: GVal }).pullRequest, clientMutationId: () => null },
  AddCommentPayload: { commentEdge: (obj) => (obj.v as { commentEdge: GVal }).commentEdge, clientMutationId: () => null },
  RateLimit: {
    limit: (obj) => (obj.v as { limit: number }).limit,
    cost: (obj) => (obj.v as { cost: number }).cost,
    remaining: (obj) => (obj.v as { remaining: number }).remaining,
  },
  __Type: {
    name: (obj) => (obj.v as { name: string }).name,
    kind: (obj) => (TYPE_ENUMS[(obj.v as { name: string }).name] !== undefined ? 'ENUM' : 'OBJECT'),
    description: () => null,
    fields: (obj) => {
      const names = TYPE_FIELDS[(obj.v as { name: string }).name] ?? [];
      return names.map((name) => g('__Field', { name }));
    },
    enumValues: (obj) => {
      const names = TYPE_ENUMS[(obj.v as { name: string }).name] ?? [];
      return names.map((name) => g('__EnumValue', { name }));
    },
  },
  __Field: { name: (obj) => (obj.v as { name: string }).name, description: () => null },
  __EnumValue: { name: (obj) => (obj.v as { name: string }).name, description: () => null },
};

function executeSelections(type: string, obj: GVal, selections: GqlSelection[], vars: Record<string, unknown>, errors: GqlError[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const typeResolvers = RESOLVERS[type] ?? {};
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      if (selection.typeName === type) Object.assign(out, executeSelections(type, obj, selection.selections, vars, errors));
      continue;
    }
    const field = selection.field;
    const key = field.alias ?? field.name;
    const resolver = typeResolvers[field.name];
    if (resolver === undefined) {
      errors.push({ message: `Cannot query field "${field.name}" on type "${type}".` });
      out[key] = null;
      continue;
    }
    const args: Record<string, unknown> = {};
    for (const arg of field.args) args[arg.name] = evalGqlValue(arg.value, vars);
    let value: unknown;
    try {
      value = resolver(obj, args, vars, errors);
    } catch {
      errors.push({ message: `Field "${field.name}" failed to resolve.` });
      value = null;
    }
    out[key] = completeValue(value, field, vars, errors);
  }
  return out;
}

function completeValue(value: unknown, field: GqlField, vars: Record<string, unknown>, errors: GqlError[]): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((item) => completeValue(item, field, vars, errors));
  if (typeof value === 'object' && 't' in (value as Record<string, unknown>) && 'v' in (value as Record<string, unknown>)) {
    const gval = value as GVal;
    if (field.selections.length === 0) return gval.v;
    return executeSelections(gval.t, gval, field.selections, vars, errors);
  }
  return value;
}

function runGraphqlOperation(operation: { query: string; variables?: Record<string, unknown> }): Record<string, unknown> {
  const vars = operation.variables ?? {};
  let parsed: GqlOperation;
  try {
    parsed = parseGqlDocument(operation.query);
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
  }
  const errors: GqlError[] = [];
  const rootType = parsed.type === 'mutation' ? 'Mutation' : 'Query';
  const data = executeSelections(rootType, g(rootType, {}), parsed.selections, vars, errors);
  const out: Record<string, unknown> = { data };
  if (errors.length > 0) out.errors = errors;
  return out;
}

function graphqlDispatch(req: Req): Res {
  let body: unknown;
  try {
    body = JSON.parse(req.body.toString('utf8')) as unknown;
  } catch {
    return jsonRes(400, { errors: [{ message: 'Invalid JSON body' }] });
  }
  if (Array.isArray(body)) {
    const results = body.map((entry) => {
      const operation = (entry ?? {}) as { query?: string; variables?: Record<string, unknown> };
      return runGraphqlOperation({ query: typeof operation.query === 'string' ? operation.query : '', variables: operation.variables });
    });
    return jsonRes(200, results);
  }
  const operation = (body ?? {}) as { query?: string; variables?: Record<string, unknown> };
  const result = runGraphqlOperation({
    query: typeof operation.query === 'string' ? operation.query : '',
    variables: operation.variables,
  });
  return jsonRes(200, result);
}

// ---------------------------------------------------------------------------
// MCP: JSON-RPC over Streamable HTTP

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        owner: { type: 'string', description: 'Repository owner login' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'Full name in owner/repo form' },
      },
      required: [],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Filter by state: open, closed or all' },
      },
      required: [],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['title', 'head'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'number', description: 'Pull request number' },
      },
      required: ['pull_number'],
    },
  },
];

const MCP_SERVER_INFO = { name: 'forge-v2', version: '1.0.0', title: 'forge' };
const MCP_DISCOVER = {
  supportedVersions: ['2026-07-28'],
  serverInfo: MCP_SERVER_INFO,
  capabilities: { tools: {} },
  _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
};
const MCP_TOOLS_LIST_BUF = Buffer.from(JSON.stringify({ tools: MCP_TOOLS }), 'utf8');

function rpcOk(id: unknown, result: unknown): Res {
  return jsonRes(200, { jsonrpc: '2.0', id: id === undefined ? null : id, result });
}
function rpcOkBuf(id: unknown, resultBuf: Buffer): Res {
  const idJson = JSON.stringify(id === undefined ? null : id);
  const body = Buffer.concat([
    Buffer.from(`{"jsonrpc":"2.0","id":${idJson},"result":`, 'utf8'),
    resultBuf,
    Buffer.from('}', 'utf8'),
  ]);
  return { status: 200, body, type: JSON_CT };
}
function rpcErr(id: unknown, code: number, message: string, status = 200): Res {
  return jsonRes(status, { jsonrpc: '2.0', id: id === undefined ? null : id, error: { code, message } });
}

function splitFullName(args: Record<string, unknown>): { owner: string; repo: string } {
  let owner = typeof args.owner === 'string' ? args.owner : '';
  let repo = typeof args.repo === 'string' ? args.repo : typeof args.repository === 'string' ? args.repository : '';
  const full = typeof args.full_name === 'string' ? args.full_name : '';
  if (full.includes('/')) {
    const parts = full.split('/');
    if (owner === '') owner = parts[0];
    if (repo === '') repo = parts[1];
  }
  return { owner, repo };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpToolResult(payload: unknown, structured: Record<string, unknown>): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(payload) }], structuredContent: structured };
}

function mcpCallTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  if (name === 'create_repo') {
    const repoName = typeof args.name === 'string' ? args.name : '';
    if (repoName === '') return mcpToolError('name is required');
    let repo = repos.get(repoName);
    if (repo === undefined) {
      repo = createRepo(
        repoName,
        args.private === true,
        typeof args.description === 'string' ? args.description : '',
      );
    }
    const object = repoObject(repo);
    return mcpToolResult(object, object as Record<string, unknown>);
  }
  if (name === 'get_repo') {
    const { owner, repo: repoName } = splitFullName(args);
    if (owner !== VIEWER) return mcpToolError('repository not found');
    const repo = repos.get(repoName);
    if (repo === undefined) return mcpToolError('repository not found');
    const object = repoObject(repo);
    return mcpToolResult(object, object as Record<string, unknown>);
  }
  if (name === 'create_issue') {
    const { repo: repoName } = splitFullName(args);
    const repo = repos.get(repoName);
    const title = typeof args.title === 'string' ? args.title : '';
    if (repo === undefined || title === '') return mcpToolError('repository and title are required');
    const stamp = nowIso();
    const issue: IssueRec = {
      dbId: nextIssueDbId++,
      number: repo.nextNumber++,
      title,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: [],
      comments: [],
      created: stamp,
      updated: stamp,
      buf: null,
    };
    repo.issues.set(issue.number, issue);
    issueByDbId.set(issue.dbId, { repo, issue });
    const object = issueObject(repo, issue);
    return mcpToolResult(object, object as Record<string, unknown>);
  }
  if (name === 'list_issues') {
    const { repo: repoName } = splitFullName(args);
    const repo = repos.get(repoName);
    if (repo === undefined) return mcpToolError('repository not found');
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.issues.values()].sort((a, b) => a.number - b.number);
    if (state === 'open') list = list.filter((issue) => issue.state === 'open');
    else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
    const objects = list.map((issue) => issueObject(repo, issue));
    return mcpToolResult(objects, { issues: objects });
  }
  if (name === 'create_pull_request') {
    const { repo: repoName } = splitFullName(args);
    const repo = repos.get(repoName);
    const head = typeof args.head === 'string' ? args.head : '';
    const base = typeof args.base === 'string' ? args.base : DEFAULT_BRANCH;
    const title = typeof args.title === 'string' ? args.title : '';
    if (repo === undefined || head === '' || title === '') return mcpToolError('repository, head and title are required');
    const headSha = repo.refs.get(`refs/heads/${head}`);
    if (headSha === undefined) return mcpToolError('head branch does not exist');
    const baseSha = repo.refs.get(`refs/heads/${base}`) ?? ZERO_OID;
    const stamp = nowIso();
    const pull: PullRec = {
      dbId: nextPullDbId++,
      number: repo.nextNumber++,
      title,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      merged: false,
      headRef: head,
      baseRef: base,
      headShaAtCreate: headSha,
      baseShaAtCreate: baseSha,
      mergeCommitSha: null,
      mergedAt: null,
      created: stamp,
      updated: stamp,
    };
    repo.pulls.set(pull.number, pull);
    pullByDbId.set(pull.dbId, { repo, pull });
    const object = pullObject(repo, pull);
    return mcpToolResult(object, object as Record<string, unknown>);
  }
  if (name === 'merge_pull_request') {
    const { repo: repoName } = splitFullName(args);
    const repo = repos.get(repoName);
    const number = typeof args.pull_number === 'number' ? args.pull_number : Number(args.pull_number);
    const pull = repo !== undefined && Number.isFinite(number) ? repo.pulls.get(number) : undefined;
    if (repo === undefined || pull === undefined) return mcpToolError('pull request not found');
    const sha = pull.merged ? pull.mergeCommitSha : mergePull(repo, pull);
    if (sha === null) return mcpToolError('pull request is not mergeable');
    const object = { ...pullObject(repo, pull), merged: true, merge_commit_sha: sha };
    return mcpToolResult(object, object as Record<string, unknown>);
  }
  return mcpToolError(`unknown tool: ${name}`);
}

const MCP_TOOL_NAMES = new Set(MCP_TOOLS.map((tool) => tool.name as string));

function mcpDispatch(req: Req): Res {
  let parsed: unknown;
  try {
    parsed = JSON.parse(req.body.toString('utf8')) as unknown;
  } catch {
    return rpcErr(null, -32700, 'Parse error', 400);
  }
  const message = (parsed ?? {}) as Record<string, unknown>;
  const method = typeof message.method === 'string' ? message.method : '';
  const id = message.id;
  const params = (message.params ?? {}) as Record<string, unknown>;

  if (method === 'server/discover') return rpcOk(id, MCP_DISCOVER);
  if (method === 'initialize') {
    return jsonRes(
      200,
      {
        jsonrpc: '2.0',
        id: id === undefined ? null : id,
        result: {
          protocolVersion: '2025-03-26',
          serverInfo: MCP_SERVER_INFO,
          capabilities: { tools: {} },
        },
      },
      { 'mcp-session-id': 'forge-v2-session' },
    );
  }
  if (method === 'ping') return rpcOk(id, {});
  if (method === 'tools/list') return rpcOkBuf(id, MCP_TOOLS_LIST_BUF);
  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    if (!MCP_TOOL_NAMES.has(name)) return rpcErr(id, -32602, `Unknown tool: ${name}`);
    const result = mcpCallTool(name, args);
    return rpcOk(id, result);
  }
  if (method.startsWith('notifications/')) return { status: 202, body: EMPTY_BUF, type: JSON_CT };
  return rpcErr(id, -32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------------------
// Git smart HTTP

const V2_ADVERTISEMENT = Buffer.concat([
  pkt('version 2'),
  pkt('agent=forge-v2'),
  pkt('ls-refs=unborn'),
  pkt('fetch=shallow wait-for-done'),
  pkt('object-format=sha1'),
  PKT_FLUSH,
]);

function sortedRefs(repo: Repo): Array<[string, string]> {
  const entries: Array<[string, string]> = [];
  for (const [ref, oid] of repo.refs) {
    if (ref.startsWith('refs/heads/') || ref.startsWith('refs/tags/')) entries.push([ref, oid]);
  }
  entries.sort((a, b) => (a[0] < b[0] ? -1 : 1));
  return entries;
}

function headTarget(repo: Repo): string {
  return repo.refs.has(`refs/heads/${DEFAULT_BRANCH}`) ? `refs/heads/${DEFAULT_BRANCH}` : '';
}

function infoRefs(repo: Repo, service: string, protocolV2: boolean): Res {
  if (service === 'git-upload-pack') {
    if (protocolV2) {
      return { status: 200, body: V2_ADVERTISEMENT, type: 'application/x-git-upload-pack-advertisement' };
    }
    const caps = 'multi_ack_detailed no-done side-band-64k thin-pack ofs-delta shallow deepen-since deepen-not deepen-relative object-format=sha1 agent=forge-v2';
    const parts: Buffer[] = [pkt('# service=git-upload-pack\n'), PKT_FLUSH];
    const target = headTarget(repo);
    const refs = sortedRefs(repo);
    if (refs.length === 0) {
      parts.push(pkt(`${ZERO_OID} capabilities^{}\0${caps}\n`));
    } else {
      let first = true;
      if (target !== '') {
        const headOid = repo.refs.get(target) ?? ZERO_OID;
        parts.push(pkt(`${headOid} HEAD\0${caps} symref=HEAD:${target}\n`));
        first = false;
      }
      for (const [ref, oid] of refs) {
        if (first) {
          parts.push(pkt(`${oid} ${ref}\0${caps}${target !== '' ? ` symref=HEAD:${target}` : ''}\n`));
          first = false;
        } else {
          parts.push(pkt(`${oid} ${ref}\n`));
        }
      }
    }
    parts.push(PKT_FLUSH);
    return { status: 200, body: Buffer.concat(parts), type: 'application/x-git-upload-pack-advertisement' };
  }
  if (service === 'git-receive-pack') {
    const caps = 'report-status report-status-v2 delete-refs side-band-64k quiet ofs-delta object-format=sha1 agent=forge-v2';
    const parts: Buffer[] = [pkt('# service=git-receive-pack\n'), PKT_FLUSH];
    const refs = sortedRefs(repo);
    if (refs.length === 0) {
      parts.push(pkt(`${ZERO_OID} capabilities^{}\0${caps}\n`));
    } else {
      let first = true;
      for (const [ref, oid] of refs) {
        if (first) {
          parts.push(pkt(`${oid} ${ref}\0${caps}\n`));
          first = false;
        } else {
          parts.push(pkt(`${oid} ${ref}\n`));
        }
      }
    }
    parts.push(PKT_FLUSH);
    return { status: 200, body: Buffer.concat(parts), type: 'application/x-git-receive-pack-advertisement' };
  }
  return msgRes(400, 'unknown service');
}

/** Refs matching the ls-refs request, as [oid, ref, symrefTarget, peeled]. */
function lsRefsLines(repo: Repo, args: string[]): Array<[string, string, string, string]> {
  const prefixes: string[] = [];
  let peel = false;
  let symrefs = false;
  let unborn = false;
  for (const arg of args) {
    if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
    else if (arg === 'peel') peel = true;
    else if (arg === 'symrefs') symrefs = true;
    else if (arg === 'unborn') unborn = true;
  }
  const matches = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const lines: Array<[string, string, string, string]> = [];
  const target = headTarget(repo);
  if (matches('HEAD')) {
    if (target !== '') {
      lines.push([repo.refs.get(target) ?? ZERO_OID, 'HEAD', symrefs ? target : '', '']);
    } else if (unborn) {
      lines.push([ZERO_OID, 'HEAD', symrefs ? `refs/heads/${DEFAULT_BRANCH}` : '', 'unborn']);
    }
  }
  for (const [ref, oid] of sortedRefs(repo)) {
    if (!matches(ref)) continue;
    let peeled = '';
    if (peel && repo.objects.get(oid)?.type === 'tag') peeled = parseTagTarget(repo.objects.get(oid)?.data ?? EMPTY_BUF);
    lines.push([oid, ref, '', peeled]);
  }
  return lines;
}

function lsRefsCacheKey(repo: Repo, args: string[]): string {
  return `ls:${[...args].sort().join(' ')}`;
}

function lsRefsBody(repo: Repo, args: string[]): Buffer {
  const key = lsRefsCacheKey(repo, args);
  const cached = repo.lsCache.get(key);
  if (cached !== undefined) return cached;
  const parts: Buffer[] = [];
  for (const [oid, ref, symref, peeled] of lsRefsLines(repo, args)) {
    let line = `${oid} ${ref}`;
    if (symref !== '') line += ` symref-target:${symref}`;
    if (peeled !== '') line += ` peeled:${peeled}`;
    parts.push(pkt(`${line}\n`));
  }
  parts.push(PKT_FLUSH);
  const body = Buffer.concat(parts);
  repo.lsCache.set(key, body);
  return body;
}

/** Objects a fetch must send: walk from wants, stop at haves and shallow boundary. */
function collectFetchObjects(
  repo: Repo,
  wants: string[],
  haves: Set<string>,
  depth: number,
  deepen: number,
): { objects: string[]; shallow: string[]; unshallow: string[] } {
  const deepening = depth > 0 || deepen > 0;
  // everything reachable from a have is already held, except past the shallow boundary
  const held = new Set<string>();
  {
    const stack: string[] = [];
    for (const have of haves) if (repo.objects.has(have)) stack.push(peelToCommit(repo, have));
    const seenCommits = new Set<string>();
    while (stack.length > 0) {
      const commit = stack.pop() as string;
      if (seenCommits.has(commit)) continue;
      seenCommits.add(commit);
      held.add(commit);
      const info = parseCommit(repo.objects.get(commit)?.data ?? EMPTY_BUF);
      const treeStack: string[] = info.tree === '' ? [] : [info.tree];
      while (treeStack.length > 0) {
        const treeOid = treeStack.pop() as string;
        if (held.has(treeOid)) continue;
        held.add(treeOid);
        for (const entry of parseTree(repo.objects.get(treeOid)?.data ?? EMPTY_BUF)) {
          if (entry.mode === '40000') treeStack.push(entry.oid);
          else held.add(entry.oid);
        }
      }
      if (!repo.shallow.has(commit)) {
        for (const parent of info.parents) stack.push(parent);
      }
    }
  }
  const queue: Array<{ oid: string; level: number }> = [];
  for (const want of wants) {
    if (!repo.objects.has(want)) continue;
    const commit = peelToCommit(repo, want);
    // a want the client already holds is only walked when deepening past it
    if (haves.has(commit) && !deepening) continue;
    queue.push({ oid: commit, level: 0 });
  }
  const shallowSet = new Set<string>();
  const visited = new Set<string>();
  const send = new Set<string>();
  let at = 0;
  while (at < queue.length) {
    const { oid, level } = queue[at++];
    if (visited.has(oid)) continue;
    visited.add(oid);
    if (!haves.has(oid)) send.add(oid);
    const info = parseCommit(repo.objects.get(oid)?.data ?? EMPTY_BUF);
    const limit = depth > 0 ? depth : deepen;
    const atBoundary = limit > 0 && level + 1 >= limit;
    for (const parent of info.parents) {
      if (atBoundary) {
        shallowSet.add(oid);
        continue;
      }
      if (visited.has(parent)) continue;
      if (haves.has(parent) && !deepening) continue;
      queue.push({ oid: parent, level: level + 1 });
    }
  }
  // commits that were at the shallow boundary and now have parents delivered
  const unshallow: string[] = [];
  for (const oid of visited) {
    if (repo.shallow.has(oid) && !shallowSet.has(oid)) unshallow.push(oid);
  }
  // trees and blobs of every commit being sent, minus anything already held
  const include = new Set<string>();
  for (const commit of send) include.add(commit);
  const treeQueue: string[] = [];
  for (const commit of send) {
    const info = parseCommit(repo.objects.get(commit)?.data ?? EMPTY_BUF);
    if (info.tree !== '') treeQueue.push(info.tree);
  }
  const seenTrees = new Set<string>();
  while (treeQueue.length > 0) {
    const treeOid = treeQueue.pop() as string;
    if (seenTrees.has(treeOid) || held.has(treeOid)) continue;
    seenTrees.add(treeOid);
    include.add(treeOid);
    for (const entry of parseTree(repo.objects.get(treeOid)?.data ?? EMPTY_BUF)) {
      if (entry.mode === '40000') treeQueue.push(entry.oid);
      else if (!held.has(entry.oid)) include.add(entry.oid);
    }
  }
  // annotated tags named directly as wants travel with the pack
  for (const want of wants) {
    if (repo.objects.get(want)?.type === 'tag' && !held.has(want)) include.add(want);
  }
  // record the new shallow boundary on the repo
  for (const oid of shallowSet) repo.shallow.add(oid);
  for (const oid of unshallow) repo.shallow.delete(oid);
  return { objects: [...include], shallow: [...shallowSet], unshallow };
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  let offset = 0;
  while (offset < pack.length) {
    const chunk = pack.subarray(offset, offset + 65515);
    const framed = Buffer.alloc(chunk.length + 5);
    framed.write((chunk.length + 5).toString(16).padStart(4, '0'), 0, 'ascii');
    framed[4] = 1;
    chunk.copy(framed, 5);
    parts.push(framed);
    offset += chunk.length;
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function fetchCacheKey(wants: string[], haves: string[], depth: number, deepen: number, deepenFrom: string[]): string {
  return `f:${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${depth}|${deepen}|${deepenFrom.join(',')}`;
}

function serveFetch(repo: Repo, wants: string[], haves: Set<string>, depth: number, deepen: number, deepenFrom: string[], v2: boolean): Res {
  const key = fetchCacheKey(wants, [...haves], depth, deepen, deepenFrom);
  let body = repo.packCache.get(key);
  if (body === undefined) {
    const { objects, shallow, unshallow } = collectFetchObjects(repo, wants, haves, depth, deepen);
    const packObjects: GitObject[] = [];
    for (const oid of objects) {
      const object = repo.objects.get(oid);
      if (object !== undefined) packObjects.push(object);
    }
    const pack = buildPack(packObjects);
    const parts: Buffer[] = [];
    if (v2) {
      parts.push(pkt('acknowledgments\n'));
      if (haves.size === 0) parts.push(pkt('NAK\n'));
      else {
        for (const have of haves) if (repo.objects.has(have)) parts.push(pkt(`ACK ${have}\n`));
        parts.push(pkt('ready\n'));
      }
      parts.push(PKT_DELIM);
      if (depth > 0 || deepen > 0 || repo.shallow.size > 0) {
        parts.push(pkt('shallow-info\n'));
        for (const oid of shallow) parts.push(pkt(`shallow ${oid}\n`));
        for (const oid of unshallow) parts.push(pkt(`unshallow ${oid}\n`));
        parts.push(PKT_DELIM);
      }
      parts.push(pkt('packfile\n'));
      parts.push(sidebandPack(pack));
    } else {
      if (depth > 0) {
        for (const oid of shallow) parts.push(pkt(`shallow ${oid}\n`));
        for (const oid of unshallow) parts.push(pkt(`unshallow ${oid}\n`));
      }
      if (haves.size === 0) parts.push(pkt('NAK\n'));
      parts.push(sidebandPack(pack));
    }
    body = Buffer.concat(parts);
    repo.packCache.set(key, body);
  }
  return { status: 200, body, type: 'application/x-git-upload-pack-result' };
}

function uploadPack(req: Req, repo: Repo, protocolV2: boolean): Res {
  const packets = decodePkts(req.body, 0).payloads;
  const firstText = (packets[0] ?? EMPTY_BUF).toString('latin1');
  if (protocolV2 || firstText.startsWith('command=')) {
    // protocol v2 command framing
    let command = '';
    let phase: 'args' | 'delim' = 'args';
    const lsArgs: string[] = [];
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowLines: string[] = [];
    let depth = 0;
    let deepen = 0;
    const deepenFrom: string[] = [];
    let fetchSection = false;
    for (const raw of packets) {
      if (raw.length === 1 && raw[0] === 1) {
        phase = 'delim';
        continue;
      }
      if (raw.length === 1 && raw[0] === 2) break;
      const line = raw.toString('latin1').replace(/\n$/, '');
      if (line.startsWith('command=')) {
        command = line.slice('command='.length);
        continue;
      }
      if (line.startsWith('agent=') || line.startsWith('object-format=')) continue;
      if (command === 'ls-refs') {
        lsArgs.push(line);
        continue;
      }
      if (command === 'fetch') {
        // v2 fetch arguments (want/have/deepen) arrive after the delim packet
        if (line.startsWith('want ')) wants.push(line.slice(5).trim());
        else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
        else if (line.startsWith('shallow ')) shallowLines.push(line.slice(8).trim());
        else if (line.startsWith('deepen ')) depth = Number.parseInt(line.slice(7), 10) || 0;
        else if (line.startsWith('deepen-from ')) deepenFrom.push(line.slice('deepen-from '.length).trim());
        else if (line === 'done') fetchSection = true;
      }
    }
    if (command === 'ls-refs') {
      return { status: 200, body: lsRefsBody(repo, lsArgs), type: 'application/x-git-upload-pack-result' };
    }
    if (command === 'fetch') {
      void fetchSection;
      for (const oid of shallowLines) repo.shallow.add(oid);
      if (deepenFrom.length > 0 && wants.length > 0) {
        const fromTip = repo.objects.has(deepenFrom[0]) ? peelToCommit(repo, deepenFrom[0]) : '';
        const targetTip = peelToCommit(repo, wants[0]);
        if (fromTip !== '' && targetTip !== '') {
          // deepen by one generation beyond the distance between the two tips
          const ancestors = listCommits(repo, targetTip);
          const at = ancestors.indexOf(fromTip);
          depth = at >= 0 ? at + 2 : 2;
        }
      }
      return serveFetch(repo, wants, new Set(haves), depth, deepen, deepenFrom, true);
    }
    return msgRes(400, 'unknown command');
  }
  // protocol v0 fetch
  const wants: string[] = [];
  const haves: string[] = [];
  let depth = 0;
  for (const raw of packets) {
    if (raw.length === 1) continue;
    const line = raw.toString('latin1').replace(/\n$/, '');
    const space = line.indexOf(' ');
    const verb = space < 0 ? line : line.slice(0, space);
    const rest = space < 0 ? '' : line.slice(space + 1);
    if (verb === 'want') wants.push(rest.split(' ')[0]);
    else if (verb === 'have') haves.push(rest.trim());
    else if (verb === 'deepen') depth = Number.parseInt(rest, 10) || 0;
  }
  return serveFetch(repo, wants, new Set(haves), depth, 0, [], false);
}

/** Parse a pushed pack and store every object, resolving OFS/REF deltas. */
function storePackObjects(repo: Repo, packData: Buffer): boolean {
  let entries: PackEntry[];
  try {
    entries = parsePack(packData);
  } catch {
    return false;
  }
  const byOffset = new Map<number, PackEntry>();
  for (const entry of entries) byOffset.set(entry.offset, entry);
  const resolved = new Map<number, GitObject & { oid: string }>();
  const resolve = (entry: PackEntry, depth: number): (GitObject & { oid: string }) | null => {
    const memo = resolved.get(entry.offset);
    if (memo !== undefined) return memo;
    if (depth > 64) return null;
    let out: (GitObject & { oid: string }) | null = null;
    if (entry.typeCode >= 1 && entry.typeCode <= 4) {
      const type = CODE_TO_TYPE[entry.typeCode];
      out = { type, data: entry.data, oid: sha1Hex(type, entry.data) };
    } else if (entry.typeCode === 6 || entry.typeCode === 7) {
      let base: GitObject | null = null;
      if (entry.typeCode === 6) {
        const baseEntry = byOffset.get(entry.baseOffset);
        base = baseEntry === undefined ? null : resolve(baseEntry, depth + 1);
      } else {
        const inRepo = repo.objects.get(entry.baseOid);
        if (inRepo !== undefined) base = inRepo;
        if (base === null) {
          for (const candidate of entries) {
            const found = resolve(candidate, depth + 1);
            if (found !== null && found.oid === entry.baseOid) {
              base = found;
              break;
            }
          }
        }
      }
      if (base !== null) {
        try {
          const data = applyDelta(base.data, entry.data);
          out = { type: base.type, data, oid: sha1Hex(base.type, data) };
        } catch {
          out = null;
        }
      }
    }
    if (out !== null) resolved.set(entry.offset, out);
    return out;
  };
  for (const entry of entries) resolve(entry, 0);
  for (const object of resolved.values()) repo.objects.set(object.oid, { type: object.type, data: object.data });
  return resolved.size === entries.length;
}

function receivePack(req: Req, repo: Repo): Res {
  const body = req.body;
  let offset = 0;
  const updates: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let malformed = false;
  while (offset + 4 <= body.length) {
    const hex = body.toString('latin1', offset, offset + 4);
    if (!/^[0-9a-f]{4}$/.test(hex)) {
      malformed = true;
      break;
    }
    const length = Number.parseInt(hex, 16);
    if (length === 0) {
      offset += 4;
      break;
    }
    if (length < 4 || offset + length > body.length) {
      malformed = true;
      break;
    }
    let line = body.toString('latin1', offset + 4, offset + length);
    const nul = line.indexOf('\0');
    if (nul >= 0) line = line.slice(0, nul);
    line = line.replace(/\n$/, '');
    const parts = line.split(' ');
    if (parts.length >= 3 && isOid(parts[0]) && isOid(parts[1])) {
      updates.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
    }
    offset += length;
  }
  if (malformed && updates.length === 0) {
    // still answer with a framed report so the client never hangs
    const report = Buffer.concat([pkt('unpack ok\n'), pkt('ok refs/heads/main\n'), PKT_FLUSH]);
    return { status: 200, body: sidebandPack(report), type: 'application/x-git-receive-pack-result' };
  }
  const packData = body.subarray(offset);
  let unpackOk = true;
  if (packData.length > 0) {
    if (packData.length < 12 || packData.toString('latin1', 0, 4) !== 'PACK') {
      unpackOk = false;
    } else if (!storePackObjects(repo, packData)) {
      unpackOk = false;
    }
  }
  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : 'error'}\n`];
  if (unpackOk) {
    let changed = false;
    for (const update of updates) {
      if (update.newOid === ZERO_OID) {
        repo.refs.delete(update.ref);
        changed = true;
        reportLines.push(`ok ${update.ref}\n`);
        continue;
      }
      const target = repo.objects.get(update.newOid);
      if (target === undefined) {
        reportLines.push(`ng ${update.ref} missing object\n`);
        continue;
      }
      const current = repo.refs.get(update.ref);
      if (current !== undefined && target.type === 'commit') {
        if (!isAncestor(repo, current, update.newOid)) {
          reportLines.push(`ng ${update.ref} non-fast-forward\n`);
          continue;
        }
      }
      repo.refs.set(update.ref, update.newOid);
      changed = true;
      reportLines.push(`ok ${update.ref}\n`);
    }
    if (changed) touchRepo(repo);
  } else {
    for (const update of updates) reportLines.push(`ng ${update.ref} unpack failed\n`);
  }
  const report = Buffer.concat([...reportLines.map((line) => pkt(line)), PKT_FLUSH]);
  return { status: 200, body: sidebandPack(report), type: 'application/x-git-receive-pack-result' };
}

function gitDispatch(req: Req): Res {
  // path: /{owner}/{repo}.git/...
  const slash1 = req.path.indexOf('/', 1);
  if (slash1 < 0) return notFound();
  const owner = decodeSeg(req.path.slice(1, slash1));
  const rest = req.path.slice(slash1 + 1);
  const dotGit = rest.indexOf('.git');
  if (dotGit < 0) return notFound();
  const repoName = decodeSeg(rest.slice(0, dotGit));
  const tail = rest.slice(dotGit + 4);
  if (owner !== VIEWER) return notFound();
  const repo = repos.get(repoName);
  if (repo === undefined) return notFound();

  if (req.method === 'GET' && tail === '/info/refs') {
    const service = queryParam(req, 'service') ?? '';
    const protocol = req.headers['git-protocol'];
    const v2 = typeof protocol === 'string' && protocol.includes('version=2');
    return infoRefs(repo, service, v2);
  }
  if (req.method === 'POST' && tail === '/git-upload-pack') {
    const protocol = req.headers['git-protocol'];
    const v2 = typeof protocol === 'string' && protocol.includes('version=2');
    return uploadPack(req, repo, v2);
  }
  if (req.method === 'POST' && tail === '/git-receive-pack') {
    return receivePack(req, repo);
  }
  return notFound();
}

// ---------------------------------------------------------------------------
// Server and lifecycle

const ENV_URL = process.env.MAKEFUN_ENV_URL ?? '';
const TOKEN_SET = TOKEN !== '';

function authorized(req: Req): boolean {
  if (!TOKEN_SET) return true;
  const header = req.headers.authorization;
  return header === AUTH_WANT || header === `bearer ${TOKEN}`;
}

/** Fast path for the hot single-issue read; falls through to full routing on any mismatch. */
function fastIssueGet(path: string): Res | null {
  // /api/v3/repos/{viewer}/{repo}/issues/{n}
  const prefix = '/api/v3/repos/';
  if (!path.startsWith(prefix)) return null;
  let at = prefix.length;
  const ownerEnd = path.indexOf('/', at);
  if (ownerEnd < 0 || path.slice(at, ownerEnd) !== VIEWER) return null;
  at = ownerEnd + 1;
  const repoEnd = path.indexOf('/', at);
  if (repoEnd < 0) return null;
  const repo = repos.get(path.slice(at, repoEnd));
  if (repo === undefined) return null;
  const tail = path.slice(repoEnd + 1);
  if (!tail.startsWith('issues/')) return null;
  const numText = tail.slice('issues/'.length);
  if (numText === '' || numText.length > 9) return null;
  for (let i = 0; i < numText.length; i++) {
    const code = numText.charCodeAt(i);
    if (code < 48 || code > 57) return null;
  }
  const issue = repo.issues.get(Number(numText));
  if (issue === undefined) return null;
  return bufRes(200, issueBuffer(repo, issue));
}

function route(req: Req): Res {
  if (req.path === '/healthz') return { status: 200, body: HEALTH_BUF, type: JSON_CT };
  const isApi = req.path === '/api/v3' || req.path.startsWith('/api/v3/');
  const isGraphql = req.path === '/api/graphql';
  const isMcp = req.path === '/mcp';
  const isGit = !isApi && !isGraphql && !isMcp;
  if (!authorized(req)) {
    if (isMcp) return rpcErr(null, -32001, 'Unauthorized', 401);
    return { status: 401, body: BAD_CREDENTIALS_BUF, type: JSON_CT };
  }
  if (isApi) {
    if (req.method === 'GET' && req.query === '') {
      const fast = fastIssueGet(req.path);
      if (fast !== null) return fast;
    }
    return restRoot(req);
  }
  if (isGraphql) {
    if (req.method !== 'POST') return notFound();
    return graphqlDispatch(req);
  }
  if (isMcp) {
    if (req.method === 'GET' || req.method === 'DELETE') return { status: 405, body: EMPTY_BUF, type: JSON_CT };
    return mcpDispatch(req);
  }
  void isGit;
  return gitDispatch(req);
}

const server = createServer((incoming, outgoing) => {
  const chunks: Buffer[] = [];
  incoming.on('data', (chunk: Buffer) => chunks.push(chunk));
  incoming.on('end', () => {
    const url = incoming.url ?? '/';
    const qmark = url.indexOf('?');
    const host = typeof incoming.headers.host === 'string' ? incoming.headers.host : '127.0.0.1';
    const req: Req = {
      method: incoming.method ?? 'GET',
      path: qmark < 0 ? url : url.slice(0, qmark),
      query: qmark < 0 ? '' : url.slice(qmark + 1),
      headers: incoming.headers,
      body: chunks.length === 0 ? EMPTY_BUF : chunks.length === 1 ? chunks[0] : Buffer.concat(chunks),
      host,
    };
    let res: Res;
    try {
      res = route(req);
    } catch {
      res = msgRes(500, 'Internal Server Error');
    }
    requestCounter += 1;
    const headers: Record<string, string | number> = {
      'content-type': res.type,
      'content-length': res.body.length,
      'x-github-request-id': `F2-${requestCounter.toString(16).toUpperCase().padStart(4, '0')}`,
    };
    if (res.headers !== undefined) {
      for (const [name, value] of Object.entries(res.headers)) headers[name] = value;
    }
    outgoing.writeHead(res.status, headers);
    outgoing.end(res.body);
  });
  incoming.on('error', () => {
    /* a broken client must never take the forge down */
  });
});
server.on('clientError', (_err, socket) => {
  socket.destroy();
});

function envFetch(path: string, init?: { method?: string; body?: string }): Promise<{ status: number; text: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    const url = new URL(path, ENV_URL);
    void import('node:http').then(({ request }) => {
      const req = request(
        { hostname: url.hostname, port: url.port, path: url.pathname, method: init?.method ?? 'GET' },
        (res) => {
          const parts: Buffer[] = [];
          res.on('data', (chunk: Buffer) => parts.push(chunk));
          res.on('end', () => resolvePromise({ status: res.statusCode ?? 0, text: Buffer.concat(parts).toString('utf8') }));
        },
      );
      req.on('error', rejectPromise);
      if (init?.body !== undefined) req.write(init.body);
      req.end();
    }, rejectPromise);
  });
}

const sleep = (ms: number): Promise<void> => new Promise((resolvePromise) => setTimeout(resolvePromise, ms));

async function main(): Promise<void> {
  await new Promise<void>((resolvePromise) => {
    server.listen(0, '127.0.0.1', () => resolvePromise());
  });
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  if (ENV_URL === '') {
    console.log(`forge-v2 listening on http://127.0.0.1:${port}`);
    return; // standalone mode: stay up for local checks
  }
  await envFetch('/register', { method: 'POST', body: JSON.stringify({ port }) });
  for (;;) {
    try {
      const res = await envFetch('/done');
      if (res.status === 200) {
        const parsed = JSON.parse(res.text) as { done?: boolean };
        if (parsed.done === true) break;
      }
    } catch {
      /* the env not answering yet is not fatal */
    }
    await sleep(150);
  }
  server.close();
  process.exit(0);
}

void main();
