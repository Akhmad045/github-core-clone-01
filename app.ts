// A standalone GitHub-compatible git forge: one process, stdlib only.
// Serves git smart HTTP (upload-pack v2 + v0, receive-pack v0), REST v3,
// GraphQL v4 and MCP over one in-memory store. Deterministic: every timestamp
// derives from MAKEFUN_TRIAL_NOW plus a monotonic counter; every id from
// counters; no wall clock, no Math.random in any response.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import {
  ZERO_OID, isOid, hashObject, parseTree, buildTree, parseCommit, buildCommit, parseTag,
  collectReachable, pktLine, pktFlush, pktDelim, decodePktLines, readPack, writePack,
  verifyPackChecksum, flattenTree, buildTreeFromFlat, isAncestor, mergeBase,
  type GitObject, type GitObjectType, type TreeEntry,
} from './git.ts';

// ---------------------------------------------------------------- deterministic identity

const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;

function fnv1a64(text: string): bigint {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    h ^= BigInt(text.charCodeAt(i));
    h = (h * 0x100000001b3n) & U64_MASK;
  }
  return h;
}
function mix64(v: bigint): bigint {
  let z = (v + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}
class Rng {
  #state: bigint;
  constructor(seed: bigint) { const m = seed & U64_MASK; this.#state = m === 0n ? SCENARIO_SEED : m; }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number { return Number(this.nextU64() >> 32n); }
  nextInt(max: number): number {
    if (max === 1) return 0;
    const range = 4294967296;
    const limit = range - (range % max);
    for (;;) { const v = this.nextU32(); if (v < limit) return v % max; }
  }
  pick<T>(items: readonly T[]): T { return items[this.nextInt(items.length)]!; }
}
const FIRST_NAMES = ['ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane'] as const;
const LAST_NAMES = ['anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer'] as const;

interface ScenarioUser { id: number; login: string; name: string; email: string; }
function scenarioUsers(): ScenarioUser[] {
  const rng = new Rng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const used = new Set<string>();
  const users: ScenarioUser[] = [];
  for (let i = 0; i < 12; i += 1) {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const base = `${first}${last}`;
    let login = base;
    let suffix = 2;
    while (used.has(login)) { login = `${base}-${suffix}`; suffix += 1; }
    used.add(login);
    users.push({ id: 1000 + i, login, name: `${first} ${last}`, email: `${login}@example.invalid` });
  }
  return users;
}
const USERS = scenarioUsers();
const VIEWER = USERS[0]!;
const STRANGER = USERS[2]!;
const VIEWER_LOGIN = VIEWER.login;

// Trial clock: MAKEFUN_TRIAL_NOW (ISO or epoch) plus a monotonic counter.
function trialNowSec(): number {
  const raw = process.env.MAKEFUN_TRIAL_NOW ?? '';
  if (raw !== '') {
    const asNum = Number(raw);
    if (Number.isFinite(asNum) && asNum > 0) return Math.floor(asNum > 1e12 ? asNum / 1000 : asNum);
    const parsed = Date.parse(raw);
    if (Number.isFinite(parsed)) return Math.floor(parsed / 1000);
  }
  return 1700000000;
}
const BASE_TIME = trialNowSec();

// ---------------------------------------------------------------- helpers

const JSON_TYPE = 'application/json; charset=utf-8';
let reqCounter = 0;
function reqId(): string { reqCounter += 1; return `req-${reqCounter.toString(36)}-${(reqCounter * 2654435761 % 100000).toString(36)}`; }

function sendJsonText(res: ServerResponse, status: number, text: string, extra: Record<string, string> = {}): void {
  const headers: Record<string, string> = { 'x-github-request-id': reqId(), ...extra };
  if (status !== 204) { headers['content-type'] = JSON_TYPE; headers['content-length'] = String(Buffer.byteLength(text)); }
  res.writeHead(status, headers);
  res.end(text);
}
function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = status === 204 ? '' : `${JSON.stringify(body)}\n`;
  const headers: Record<string, string> = { 'x-github-request-id': reqId(), ...extra };
  if (status !== 204) { headers['content-type'] = JSON_TYPE; headers['content-length'] = String(Buffer.byteLength(text)); }
  res.writeHead(status, headers);
  res.end(text);
}
function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string, extra: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': String(body.length), 'x-github-request-id': reqId(), ...extra });
  res.end(body);
}
function errJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message }, { 'x-oauth-scopes': 'repo, read:org' });
}
function b64encode(text: string): string { return Buffer.from(text, 'utf8').toString('base64'); }
function b64decode(s: string): Buffer { return Buffer.from(s.replace(/[\r\n\t ]+/g, ''), 'base64'); }
function iso(sec: number): string { return new Date(sec * 1000).toISOString(); }
function sha1hex(s: string): string { return createHash('sha1').update(s, 'utf8').digest('hex'); }

interface Ctx { req: IncomingMessage; res: ServerResponse; method: string; segs: string[]; query: URLSearchParams; body: Buffer; host: string; }

function pathSegs(url: string): { segs: string[]; query: URLSearchParams } {
  let path = '/';
  let search = '';
  try {
    const u = new URL(url, 'http://x');
    path = u.pathname;
    search = u.search;
  } catch { path = url.split('?')[0] ?? '/'; }
  const segs = path.split('/').filter((s) => s !== '').map((s) => { try { return decodeURIComponent(s); } catch { return s; } });
  return { segs, query: new URLSearchParams(search) };
}

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
function authed(req: IncomingMessage): boolean {
  const h = req.headers.authorization ?? '';
  if (!h.startsWith('Bearer ')) return false;
  const tok = h.slice(7);
  if (tok === '') return false;
  if (TOKEN !== '') return tok === TOKEN;
  return true;
}

// ---------------------------------------------------------------- store

interface Label { id: number; name: string; color: string; }
interface Issue {
  id: number; number: number; title: string; body: string; state: 'open' | 'closed';
  labels: string[]; seq: number; createdAt: string; updatedAt: string;
}
interface Comment { id: number; body: string; createdAt: string; }
interface Pull {
  id: number; number: number; title: string; body: string; state: 'open' | 'closed';
  head: string; base: string; merged: boolean; mergedAt: string | null; mergeCommitSha: string | null;
  seq: number; createdAt: string; updatedAt: string;
}
interface Repo {
  id: number; name: string; owner: string; description: string; isPrivate: boolean;
  defaultBranch: string; createdAt: string; updatedAt: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  issues: Issue[]; pulls: Pull[]; labels: Map<string, Label>;
  comments: Map<number, Comment[]>;
  nextNumber: number; nextLabelId: number; seq: number;
}

class Store {
  repos = new Map<string, Repo>();
  nextRepoId = 1;
  nextIssueId = 1;
  nextCommentId = 1;
  commitSeq = 0;
  stampSeq = 0;
  nowSec(): number { this.stampSeq += 1; return BASE_TIME + this.stampSeq; }
  key(owner: string, name: string): string { return `${owner}/${name}`; }
  getRepo(owner: string, name: string): Repo | undefined {
    if (owner !== VIEWER_LOGIN) return undefined;
    return this.repos.get(this.key(owner, name));
  }
  createRepo(name: string, isPrivate: boolean, description: string): Repo {
    const now = iso(this.nowSec());
    const repo: Repo = {
      id: this.nextRepoId++, name, owner: VIEWER_LOGIN, description, isPrivate,
      defaultBranch: 'main', createdAt: now, updatedAt: now,
      refs: new Map(), objects: new Map(), issues: [], pulls: [], labels: new Map(),
      comments: new Map(), nextNumber: 1, nextLabelId: 1, seq: 0,
    };
    this.repos.set(this.key(VIEWER_LOGIN, name), repo);
    return repo;
  }
  deleteRepo(owner: string, name: string): boolean { return this.repos.delete(this.key(owner, name)); }
  putObject(repo: Repo, type: GitObjectType, data: Buffer): string {
    const oid = hashObject(type, data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
    return oid;
  }
  lookup(repo: Repo): (oid: string) => GitObject | undefined { return (oid) => repo.objects.get(oid); }
  refTip(repo: Repo, ref: string): string | undefined { return repo.refs.get(ref); }
  branchTip(repo: Repo, branch: string): string | undefined { return repo.refs.get(`refs/heads/${branch}`); }
  resolveRef(repo: Repo, ref: string): string | undefined {
    // branch name, full ref, or commit oid
    if (ref.startsWith('refs/')) return repo.refs.get(ref);
    const b = repo.refs.get(`refs/heads/${ref}`);
    if (b) return b;
    const t = repo.refs.get(`refs/tags/${ref}`);
    if (t) return t;
    if (isOid(ref) && repo.objects.has(ref)) return ref;
    return undefined;
  }
  /** Create a commit on `branch` (creating the branch from the default tip when missing). */
  commitOnBranch(repo: Repo, branch: string, treeOid: string, message: string, parents?: string[]): string {
    const tip = this.branchTip(repo, branch);
    const ps = parents ?? (tip ? [tip] : []);
    const ts = BASE_TIME + (this.commitSeq++);
    const ident = `${VIEWER.name} <${VIEWER.email}>`;
    const msg = message.endsWith('\n') ? message : `${message}\n`;
    const data = buildCommit(treeOid, ps, msg, ident, ident, ts);
    const oid = this.putObject(repo, 'commit', data);
    repo.refs.set(`refs/heads/${branch}`, oid);
    return oid;
  }
  /** Replace path in the tree at `baseTreeOid` (or empty tree) with blob content (or delete when content null). */
  setPath(repo: Repo, baseTreeOid: string | null, path: string, content: Buffer | null): { treeOid: string; blobOid: string | null } {
    const flat = baseTreeOid ? flattenTree(baseTreeOid, this.lookup(repo)) : new Map<string, { oid: string; mode: string }>();
    let blobOid: string | null = null;
    if (content === null) flat.delete(path);
    else { blobOid = this.putObject(repo, 'blob', content); flat.set(path, { oid: blobOid, mode: '100644' }); }
    const treeOid = buildTreeFromFlat(flat, (t, d) => this.putObject(repo, t, d));
    return { treeOid, blobOid };
  }
  treeAt(repo: Repo, commitOid: string): string { return parseCommit(repo.objects.get(commitOid)!.data).tree; }
}

const store = new Store();

// Serialized single-issue responses, keyed `${repo.id}:${issue.number}`. The read
// workload GETs one issue thousands of times; every mutation of an issue (PATCH,
// comment add, label change, GraphQL close) invalidates its entry.
const issueJsonCache = new Map<string, string>();
function invalidateIssueCache(repo: Repo, number?: number): void {
  if (number === undefined) {
    const prefix = `${repo.id}:`;
    for (const k of [...issueJsonCache.keys()]) if (k.startsWith(prefix)) issueJsonCache.delete(k);
  } else {
    issueJsonCache.delete(`${repo.id}:${number}`);
  }
}

// ---------------------------------------------------------------- REST shapes

function userJson(login: string): Record<string, unknown> {
  const u = USERS.find((x) => x.login === login) ?? VIEWER;
  return { login: u.login, id: u.id, name: u.name, email: u.email, type: 'User', avatar_url: '', html_url: '' };
}
function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, owner: userJson(repo.owner),
    private: repo.isPrivate, description: repo.description, default_branch: repo.defaultBranch,
    html_url: '', url: `/api/v3/repos/${repo.owner}/${repo.name}`, created_at: repo.createdAt, updated_at: repo.updatedAt,
    has_issues: true, has_projects: false, has_wiki: false, fork: false, archived: false, disabled: false,
    open_issues_count: repo.issues.filter((i) => i.state === 'open').length,
  };
}
function labelJson(l: Label, repo: Repo): Record<string, unknown> {
  return { id: l.id, name: l.name, color: l.color, description: '', url: `/api/v3/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(l.name)}` };
}
function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id, number: issue.number, title: issue.title, body: issue.body, state: issue.state,
    labels: issue.labels.map((n) => { const l = repo.labels.get(n); return l ? labelJson(l, repo) : { id: 0, name: n, color: 'ededed', description: '' }; }),
    user: userJson(repo.owner), created_at: issue.createdAt, updated_at: issue.updatedAt,
    comments: (repo.comments.get(issue.number) ?? []).length, url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    html_url: '', repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
  };
}
function pullHeadBase(repo: Repo, pr: Pull): { head: Record<string, unknown>; base: Record<string, unknown> } {
  const headSha = store.branchTip(repo, pr.head) ?? '';
  const baseSha = store.branchTip(repo, pr.base) ?? '';
  return {
    head: { ref: pr.head, sha: headSha, label: `${repo.owner}:${pr.head}`, user: userJson(repo.owner), repo: repoJson(repo) },
    base: { ref: pr.base, sha: baseSha, label: `${repo.owner}:${pr.base}`, user: userJson(repo.owner), repo: repoJson(repo) },
  };
}
function pullJson(repo: Repo, pr: Pull): Record<string, unknown> {
  const { head, base } = pullHeadBase(repo, pr);
  return {
    id: pr.id, number: pr.number, title: pr.title, body: pr.body, state: pr.state,
    head, base, merged: pr.merged, merged_at: pr.mergedAt, merge_commit_sha: pr.mergeCommitSha,
    user: userJson(repo.owner), created_at: pr.createdAt, updated_at: pr.updatedAt,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pr.number}`, html_url: '',
    draft: false, locked: false,
  };
}

function parseJsonBody(ctx: Ctx): { ok: true; value: unknown } | { ok: false } {
  if (ctx.body.length === 0) return { ok: true, value: {} };
  try { return { ok: true, value: JSON.parse(ctx.body.toString('utf8')) }; }
  catch { return { ok: false }; }
}
function asRecord(v: unknown): Record<string, unknown> { return (v !== null && typeof v === 'object' && !Array.isArray(v)) ? v as Record<string, unknown> : {}; }
function asString(v: unknown, d = ''): string { return typeof v === 'string' ? v : d; }
function asBool(v: unknown, d = false): boolean { return typeof v === 'boolean' ? v : d; }

function pageParams(ctx: Ctx): { page: number; perPage: number } {
  const page = Math.max(1, parseInt(ctx.query.get('page') ?? '1', 10) || 1);
  const perPage = Math.min(100, Math.max(1, parseInt(ctx.query.get('per_page') ?? '30', 10) || 30));
  return { page, perPage };
}
function paginate<T>(ctx: Ctx, items: T[]): { page: T[]; total: number; pageNum: number; perPage: number } {
  const { page, perPage } = pageParams(ctx);
  const total = items.length;
  return { page: items.slice((page - 1) * perPage, page * perPage), total, pageNum: page, perPage };
}
function linkHeader(ctx: Ctx, total: number, pageNum: number, perPage: number): string {
  const pages = Math.max(1, Math.ceil(total / perPage));
  if (pages <= 1) return '';
  const base = `http://${ctx.host}${ctx.req.url!.split('?')[0]}`;
  const mk = (p: number): string => {
    const q = new URLSearchParams(ctx.query);
    q.set('page', String(p));
    q.set('per_page', String(perPage));
    return `<${base}?${q.toString()}>`;
  };
  const parts: string[] = [];
  if (pageNum < pages) { parts.push(`${mk(pageNum + 1)}; rel="next"`); parts.push(`${mk(pages)}; rel="last"`); }
  if (pageNum > 1) { parts.push(`${mk(1)}; rel="first"`); parts.push(`${mk(pageNum - 1)}; rel="prev"`); }
  return parts.join(', ');
}
function sendList(ctx: Ctx, items: unknown[]): void {
  const { page, total, pageNum, perPage } = paginate(ctx, items);
  const link = linkHeader(ctx, total, pageNum, perPage);
  sendJson(ctx.res, 200, page, { 'x-oauth-scopes': 'repo, read:org', ...(link ? { link } : {}) });
}

// ---------------------------------------------------------------- issue / pull creation (shared by REST, GraphQL, MCP)

function createIssueIn(repo: Repo, title: string, body: string, labelNames: string[]): { issue?: Issue; error?: { status: number; message: string } } {
  for (const n of labelNames) if (!repo.labels.has(n)) return { error: { status: 422, message: `Label does not exist: ${n}` } };
  repo.seq += 1;
  const now = iso(store.nowSec());
  const issue: Issue = { id: store.nextIssueId++, number: repo.nextNumber++, title, body, state: 'open', labels: [...labelNames], seq: repo.seq, createdAt: now, updatedAt: now };
  repo.issues.push(issue);
  repo.comments.set(issue.number, []);
  return { issue };
}

function lineDiffStats(a: string, b: string): { additions: number; deletions: number } {
  const count = (lines: string[]): Map<string, number> => {
    const m = new Map<string, number>();
    for (const l of lines) m.set(l, (m.get(l) ?? 0) + 1);
    return m;
  };
  const ma = count(a.split('\n'));
  const mb = count(b.split('\n'));
  let additions = 0;
  let deletions = 0;
  for (const [l, n] of mb) additions += Math.max(0, n - (ma.get(l) ?? 0));
  for (const [l, n] of ma) deletions += Math.max(0, n - (mb.get(l) ?? 0));
  return { additions, deletions };
}

interface FileDiff { filename: string; status: 'added' | 'modified' | 'removed'; additions: number; deletions: number; changes: number; }
function diffTrees(repo: Repo, baseTree: string, headTree: string): FileDiff[] {
  const bf = flattenTree(baseTree, store.lookup(repo));
  const hf = flattenTree(headTree, store.lookup(repo));
  const paths = new Set([...bf.keys(), ...hf.keys()]);
  const out: FileDiff[] = [];
  for (const p of [...paths].sort()) {
    const b = bf.get(p);
    const h = hf.get(p);
    if (b && !h) { out.push({ filename: p, status: 'removed', additions: 0, deletions: 1, changes: 1 }); continue; }
    if (!b && h) {
      const data = repo.objects.get(h.oid)!.data.toString('utf8');
      const adds = data === '' ? 0 : data.split('\n').length;
      out.push({ filename: p, status: 'added', additions: adds, deletions: 0, changes: adds });
      continue;
    }
    if (b && h && b.oid !== h.oid) {
      const aTxt = repo.objects.get(b.oid)!.data.toString('utf8');
      const bTxt = repo.objects.get(h.oid)!.data.toString('utf8');
      const { additions, deletions } = lineDiffStats(aTxt, bTxt);
      out.push({ filename: p, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return out;
}

/** Three-way merge analysis: conflict if both sides changed the same path differently. */
interface MergePlan { conflict: boolean; resultTree: string | null; }
function planMerge(repo: Repo, pr: Pull): MergePlan {
  const headTip = store.branchTip(repo, pr.head);
  const baseTip = store.branchTip(repo, pr.base);
  if (!headTip || !baseTip) return { conflict: true, resultTree: null };
  const mb = mergeBase(headTip, baseTip, store.lookup(repo));
  const mbTree = mb ? store.treeAt(repo, mb) : null;
  const headTree = store.treeAt(repo, headTip);
  const baseTree = store.treeAt(repo, baseTip);
  const mbFlat = mbTree ? flattenTree(mbTree, store.lookup(repo)) : new Map<string, { oid: string; mode: string }>();
  const headFlat = flattenTree(headTree, store.lookup(repo));
  const baseFlat = flattenTree(baseTree, store.lookup(repo));
  const result = new Map(baseFlat);
  const paths = new Set([...mbFlat.keys(), ...headFlat.keys(), ...baseFlat.keys()]);
  for (const p of paths) {
    const m = mbFlat.get(p);
    const h = headFlat.get(p);
    const b = baseFlat.get(p);
    const same = (x?: { oid: string }, y?: { oid: string }): boolean => (x?.oid ?? null) === (y?.oid ?? null);
    const headChanged = !same(m, h);
    const baseChanged = !same(m, b);
    if (headChanged && baseChanged && !same(h, b)) return { conflict: true, resultTree: null };
    if (headChanged) {
      if (h) result.set(p, h); else result.delete(p);
    }
  }
  const treeOid = buildTreeFromFlat(result, (t, d) => store.putObject(repo, t, d));
  return { conflict: false, resultTree: treeOid };
}

function createPullIn(repo: Repo, head: string, base: string, title: string, body: string): { pull?: Pull; error?: { status: number; message: string } } {
  const headTip = store.branchTip(repo, head);
  const baseTip = store.branchTip(repo, base);
  if (!headTip || !baseTip) return { error: { status: 422, message: 'Invalid head or base branch' } };
  if (repo.pulls.some((p) => p.head === head && p.base === base && p.state === 'open')) {
    return { error: { status: 422, message: 'A pull request already exists for these branches' } };
  }
  repo.seq += 1;
  const now = iso(store.nowSec());
  const pr: Pull = {
    id: store.nextIssueId++, number: repo.nextNumber++, title, body, state: 'open',
    head, base, merged: false, mergedAt: null, mergeCommitSha: null, seq: repo.seq, createdAt: now, updatedAt: now,
  };
  repo.pulls.push(pr);
  return { pull: pr };
}

function mergePullIn(repo: Repo, pr: Pull, mergeMethod: string): { sha?: string; error?: { status: number; message: string } } {
  if (pr.merged || pr.state === 'closed') return { error: { status: 405, message: 'Pull request is already merged or closed' } };
  const baseTip = store.branchTip(repo, pr.base);
  const headTip = store.branchTip(repo, pr.head);
  if (!baseTip || !headTip) return { error: { status: 405, message: 'Pull request cannot be merged' } };
  const plan = planMerge(repo, pr);
  if (plan.conflict || !plan.resultTree) return { error: { status: 405, message: 'Merge conflict' } };
  const message = `Merge pull request #${pr.number} from ${repo.owner}/${pr.head}\n\n${pr.title}`;
  const sha = store.commitOnBranch(repo, pr.base, plan.resultTree, message, [baseTip]);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = iso(store.nowSec());
  pr.mergeCommitSha = sha;
  pr.updatedAt = pr.mergedAt;
  void mergeMethod;
  return { sha };
}

function prMergeable(repo: Repo, pr: Pull): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pr.merged) return 'CONFLICTING';
  if (!store.branchTip(repo, pr.head) || !store.branchTip(repo, pr.base)) return 'UNKNOWN';
  return planMerge(repo, pr).conflict ? 'CONFLICTING' : 'MERGEABLE';
}

// ---------------------------------------------------------------- REST router

async function handleRest(ctx: Ctx): Promise<boolean> {
  const { res, method, segs, query } = ctx;
  if (segs[0] !== 'api' || segs[1] !== 'v3') return false;
  if (!authed(ctx.req)) { errJson(res, 401, 'Requires authentication'); return true; }
  const rest = segs.slice(2);

  // GET /api/v3/ and /api/v3/meta
  if (rest.length === 0) {
    if (method !== 'GET') { errJson(res, 404, 'Not Found'); return true; }
    sendJson(res, 200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (rest.length === 1 && rest[0] === 'meta') {
    if (method !== 'GET') { errJson(res, 404, 'Not Found'); return true; }
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  // GET /api/v3/user
  if (rest.length === 1 && rest[0] === 'user') {
    if (method !== 'GET') { errJson(res, 404, 'Not Found'); return true; }
    sendJson(res, 200, userJson(VIEWER_LOGIN), { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  // /api/v3/user/repos
  if (rest.length === 2 && rest[0] === 'user' && rest[1] === 'repos') {
    if (method === 'GET') {
      const list = [...store.repos.values()].sort((a, b) => a.id - b.id).map((r) => repoJson(r));
      sendList(ctx, list);
      return true;
    }
    if (method === 'POST') {
      const parsed = parseJsonBody(ctx);
      if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
      const body = asRecord(parsed.value);
      const name = asString(body.name);
      if (!name || !/^[A-Za-z0-9._-]+$/.test(name)) { errJson(res, 422, 'Repository name is required'); return true; }
      const existing = store.getRepo(VIEWER_LOGIN, name);
      if (existing) { errJson(res, 422, 'Repository creation failed. Name already exists on this account'); return true; }
      const repo = store.createRepo(name, asBool(body.private), asString(body.description));
      sendJson(res, 201, repoJson(repo), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    errJson(res, 404, 'Not Found'); return true;
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (rest[0] === 'repos' && rest.length >= 3) {
    const owner = rest[1]!;
    const name = rest[2]!;
    const repo = store.getRepo(owner, name);
    const tail = rest.slice(3);
    if (!repo) { errJson(res, 404, 'Not Found'); return true; }
    const scopes = { 'x-oauth-scopes': 'repo, read:org' };

    // GET/PATCH/DELETE /repos/{o}/{r}
    if (tail.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(repo), scopes); return true; }
      if (method === 'PATCH') {
        const parsed = parseJsonBody(ctx);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const body = asRecord(parsed.value);
        if (typeof body.description === 'string') repo.description = body.description;
        repo.updatedAt = iso(store.nowSec());
        sendJson(res, 200, repoJson(repo), scopes);
        return true;
      }
      if (method === 'DELETE') { store.deleteRepo(owner, name); sendJson(res, 204, null, scopes); return true; }
      errJson(res, 404, 'Not Found'); return true;
    }

    // branches
    if (tail[0] === 'branches') {
      if (tail.length === 1 && method === 'GET') {
        const out: unknown[] = [];
        for (const [ref, oid] of [...repo.refs.entries()].filter(([r]) => r.startsWith('refs/heads/')).sort(([a], [b]) => (a < b ? -1 : 1))) {
          out.push({ name: ref.slice('refs/heads/'.length), commit: { sha: oid }, protected: false });
        }
        sendList(ctx, out);
        return true;
      }
      if (tail.length === 2 && method === 'GET') {
        const tip = store.branchTip(repo, tail[1]!);
        if (!tip) { errJson(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { name: tail[1], commit: { sha: tip }, protected: false }, scopes);
        return true;
      }
      errJson(res, 404, 'Not Found'); return true;
    }

    // git refs
    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'POST' && tail.length === 2) {
        const parsed = parseJsonBody(ctx);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const body = asRecord(parsed.value);
        const ref = asString(body.ref);
        const sha = asString(body.sha);
        if (!/^refs\/(heads|tags)\//.test(ref) || !isOid(sha) || !repo.objects.has(sha)) { errJson(res, 422, 'Invalid ref or sha'); return true; }
        if (repo.refs.has(ref)) { errJson(res, 422, 'Reference already exists'); return true; }
        repo.refs.set(ref, sha);
        sendJson(res, 201, { ref, object: { sha, type: 'commit' } }, scopes);
        return true;
      }
      if (method === 'GET' && tail.length >= 3) {
        const ref = `refs/${tail.slice(2).join('/')}`;
        const oid = repo.refs.get(ref);
        if (!oid) { errJson(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { ref, object: { sha: oid, type: 'commit' } }, scopes);
        return true;
      }
      errJson(res, 404, 'Not Found'); return true;
    }

    // commits
    if (tail[0] === 'commits') {
      if (method === 'GET' && tail.length === 1) {
        const ref = query.get('sha');
        const tip = ref ? store.resolveRef(repo, ref) : store.branchTip(repo, repo.defaultBranch);
        if (!tip) { sendJson(res, 200, [], scopes); return true; }
        const seen = new Set<string>();
        const out: unknown[] = [];
        const queue = [tip];
        while (queue.length) {
          const oid = queue.shift()!;
          if (seen.has(oid)) continue;
          seen.add(oid);
          const obj = repo.objects.get(oid);
          if (!obj || obj.type !== 'commit') continue;
          const c = parseCommit(obj.data);
          // The stored git object carries the message with a trailing newline;
          // the REST view presents it exactly as it was sent.
          const displayMessage = c.message.endsWith('\n') ? c.message.slice(0, -1) : c.message;
          out.push({ sha: oid, commit: { message: displayMessage, author: { name: c.author, date: iso(BASE_TIME) }, committer: { name: c.committer, date: iso(BASE_TIME) } }, parents: c.parents.map((p) => ({ sha: p })) });
          for (const p of c.parents) queue.push(p);
        }
        sendList(ctx, out);
        return true;
      }
      errJson(res, 404, 'Not Found'); return true;
    }

    // contents
    if (tail[0] === 'contents') {
      const path = tail.slice(1).join('/');
      if (method === 'GET') {
        const ref = query.get('ref') ?? undefined;
        const tip = ref ? store.resolveRef(repo, ref) : store.branchTip(repo, repo.defaultBranch);
        if (!tip) { errJson(res, 404, 'Not Found'); return true; }
        const treeOid = store.treeAt(repo, tip);
        const flat = flattenTree(treeOid, store.lookup(repo));
        const entry = flat.get(path);
        if (entry) {
          const data = repo.objects.get(entry.oid)!.data;
          sendJson(res, 200, {
            type: 'file', encoding: 'base64', content: data.toString('base64'), sha: entry.oid,
            size: data.length, name: path.split('/').pop(), path, url: `/api/v3/repos/${owner}/${name}/contents/${path}`,
          }, scopes);
          return true;
        }
        // directory listing (path '' means root)
        const prefix = path === '' ? '' : `${path}/`;
        const children = new Map<string, { type: string; oid: string }>();
        for (const [p, e] of flat) {
          if (!p.startsWith(prefix)) continue;
          const rest2 = p.slice(prefix.length);
          const seg = rest2.split('/')[0]!;
          if (rest2.includes('/')) children.set(seg, { type: 'dir', oid: '' });
          else children.set(seg, { type: 'file', oid: e.oid });
        }
        if (path === '' || children.size > 0) {
          const out = [...children.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([n, c]) => ({
            type: c.type, name: n, path: prefix + n, sha: c.oid,
            size: c.type === 'file' ? repo.objects.get(c.oid)!.data.length : 0,
            url: `/api/v3/repos/${owner}/${name}/contents/${prefix}${n}`,
          }));
          sendList(ctx, out);
          return true;
        }
        errJson(res, 404, 'Not Found'); return true;
      }
      if (method === 'PUT') {
        const parsed = parseJsonBody(ctx);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const body = asRecord(parsed.value);
        const message = asString(body.message, 'Update file');
        const content = typeof body.content === 'string' ? b64decode(body.content) : Buffer.alloc(0);
        const branch = asString(body.branch, repo.defaultBranch);
        const wantSha = asString(body.sha);
        const tip = store.branchTip(repo, branch);
        const baseTree = tip ? store.treeAt(repo, tip) : null;
        const flat = baseTree ? flattenTree(baseTree, store.lookup(repo)) : new Map();
        const existing = flat.get(path);
        const isNew = !existing;
        if (existing && wantSha !== '' && wantSha !== existing.oid) { errJson(res, 409, 'sha does not match the latest commit'); return true; }
        const { treeOid, blobOid } = store.setPath(repo, baseTree, path, content);
        const sha = store.commitOnBranch(repo, branch, treeOid, message);
        sendJson(res, isNew ? 201 : 200, {
          content: { name: path.split('/').pop(), path, sha: blobOid, size: content.length, type: 'file', encoding: 'base64', content: content.toString('base64') },
          commit: { sha, message, author: { name: VIEWER.name, email: VIEWER.email }, committer: { name: VIEWER.name, email: VIEWER.email } },
        }, scopes);
        return true;
      }
      if (method === 'DELETE') {
        const parsed = parseJsonBody(ctx);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const body = asRecord(parsed.value);
        const message = asString(body.message, 'Delete file');
        const wantSha = asString(body.sha);
        const branch = asString(body.branch, repo.defaultBranch);
        const tip = store.branchTip(repo, branch);
        if (!tip) { errJson(res, 404, 'Not Found'); return true; }
        const flat = flattenTree(store.treeAt(repo, tip), store.lookup(repo));
        const existing = flat.get(path);
        if (!existing) { errJson(res, 404, 'Not Found'); return true; }
        if (wantSha !== '' && wantSha !== existing.oid) { errJson(res, 409, 'sha does not match the latest commit'); return true; }
        const { treeOid } = store.setPath(repo, store.treeAt(repo, tip), path, null);
        const sha = store.commitOnBranch(repo, branch, treeOid, message);
        sendJson(res, 200, { commit: { sha, message } }, scopes);
        return true;
      }
      errJson(res, 404, 'Not Found'); return true;
    }

    // labels
    if (tail[0] === 'labels') {
      if (method === 'POST' && tail.length === 1) {
        const parsed = parseJsonBody(ctx);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const body = asRecord(parsed.value);
        const name2 = asString(body.name);
        const color = asString(body.color, 'ededed');
        if (!name2) { errJson(res, 422, 'Label name is required'); return true; }
        let label = repo.labels.get(name2);
        if (!label) { label = { id: repo.nextLabelId++, name: name2, color }; repo.labels.set(name2, label); invalidateIssueCache(repo); }
        sendJson(res, 201, labelJson(label, repo), scopes);
        return true;
      }
      if (method === 'GET' && tail.length === 1) {
        sendList(ctx, [...repo.labels.values()].map((l) => labelJson(l, repo)));
        return true;
      }
      errJson(res, 404, 'Not Found'); return true;
    }

    // issues
    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'POST') {
          const parsed = parseJsonBody(ctx);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
          const body = asRecord(parsed.value);
          const labelNames: string[] = Array.isArray(body.labels) ? body.labels.map((x) => typeof x === 'string' ? x : asString(asRecord(x).name)) : [];
          const r = createIssueIn(repo, asString(body.title), asString(body.body), labelNames);
          if (r.error) { errJson(res, r.error.status, r.error.message); return true; }
          sendJson(res, 201, issueJson(repo, r.issue!), scopes);
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const sort = query.get('sort') ?? 'created';
          const direction = query.get('direction') ?? 'desc';
          let list = [...repo.issues];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          const dir = direction === 'asc' ? 1 : -1;
          if (sort === 'created' || sort === 'updated') list.sort((a, b) => (a.seq - b.seq) * dir);
          sendList(ctx, list.map((i) => issueJson(repo, i)));
          return true;
        }
        errJson(res, 404, 'Not Found'); return true;
      }
      const n = Number(tail[1]);
      if (!Number.isInteger(n)) { errJson(res, 404, 'Not Found'); return true; }
      const issue = repo.issues.find((i) => i.number === n);
      if (tail.length === 2) {
        if (!issue) { errJson(res, 404, 'Not Found'); return true; }
        if (method === 'GET') {
          const key = `${repo.id}:${issue.number}`;
          const cached = issueJsonCache.get(key);
          if (cached !== undefined) { sendJsonText(res, 200, cached, scopes); return true; }
          const text = `${JSON.stringify(issueJson(repo, issue))}\n`;
          issueJsonCache.set(key, text);
          sendJsonText(res, 200, text, scopes);
          return true;
        }
        if (method === 'PATCH') {
          const parsed = parseJsonBody(ctx);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
          const body = asRecord(parsed.value);
          if (typeof body.title === 'string') issue.title = body.title;
          if (typeof body.body === 'string') issue.body = body.body;
          if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
          if (Array.isArray(body.labels)) {
            const names = body.labels.map((x) => typeof x === 'string' ? x : asString(asRecord(x).name));
            for (const nm of names) if (!repo.labels.has(nm)) { errJson(res, 422, `Label does not exist: ${nm}`); return true; }
            issue.labels = names;
          }
          issue.updatedAt = iso(store.nowSec());
          invalidateIssueCache(repo, issue.number);
          sendJson(res, 200, issueJson(repo, issue), scopes);
          return true;
        }
        errJson(res, 404, 'Not Found'); return true;
      }
      if (tail.length === 3 && tail[2] === 'comments') {
        if (!issue) { errJson(res, 404, 'Not Found'); return true; }
        if (method === 'GET') {
          const list = (repo.comments.get(n) ?? []).map((c) => ({ id: c.id, body: c.body, user: userJson(repo.owner), created_at: c.createdAt, updated_at: c.createdAt }));
          sendList(ctx, list);
          return true;
        }
        if (method === 'POST') {
          const parsed = parseJsonBody(ctx);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
          const body = asRecord(parsed.value);
          const now = iso(store.nowSec());
          const comment: Comment = { id: store.nextCommentId++, body: asString(body.body), createdAt: now };
          repo.comments.get(n)!.push(comment);
          invalidateIssueCache(repo, n);
          sendJson(res, 201, { id: comment.id, body: comment.body, user: userJson(repo.owner), created_at: now, updated_at: now }, scopes);
          return true;
        }
        errJson(res, 404, 'Not Found'); return true;
      }
      errJson(res, 404, 'Not Found'); return true;
    }

    // pulls
    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'POST') {
          const parsed = parseJsonBody(ctx);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
          const body = asRecord(parsed.value);
          const head = asString(body.head).split(':').pop()!;
          const base = asString(body.base).split(':').pop()!;
          const r = createPullIn(repo, head, base, asString(body.title), asString(body.body));
          if (r.error) { errJson(res, r.error.status, r.error.message); return true; }
          sendJson(res, 201, pullJson(repo, r.pull!), scopes);
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...repo.pulls];
          if (state !== 'all') list = list.filter((p) => p.state === state);
          list.sort((a, b) => b.seq - a.seq);
          sendList(ctx, list.map((p) => pullJson(repo, p)));
          return true;
        }
        errJson(res, 404, 'Not Found'); return true;
      }
      const n = Number(tail[1]);
      if (!Number.isInteger(n)) { errJson(res, 404, 'Not Found'); return true; }
      const pr = repo.pulls.find((p) => p.number === n);
      if (tail.length === 2) {
        if (!pr) { errJson(res, 404, 'Not Found'); return true; }
        if (method === 'GET') { sendJson(res, 200, pullJson(repo, pr), scopes); return true; }
        errJson(res, 404, 'Not Found'); return true;
      }
      if (tail.length === 3 && tail[2] === 'files') {
        if (!pr) { errJson(res, 404, 'Not Found'); return true; }
        if (method === 'GET') {
          const headTip = store.branchTip(repo, pr.head);
          const baseTip = store.branchTip(repo, pr.base);
          if (!headTip || !baseTip) { sendJson(res, 200, [], scopes); return true; }
          const mb = mergeBase(headTip, baseTip, store.lookup(repo));
          const mbTree = mb ? store.treeAt(repo, mb) : null;
          const headTree = store.treeAt(repo, headTip);
          const diffs = mbTree ? diffTrees(repo, mbTree, headTree) : diffTrees(repo, baseTreeOf(repo, baseTip), headTree);
          sendList(ctx, diffs);
          return true;
        }
        errJson(res, 404, 'Not Found'); return true;
      }
      if (tail.length === 3 && tail[2] === 'merge') {
        if (!pr) { errJson(res, 404, 'Not Found'); return true; }
        if (method === 'PUT') {
          const parsed = parseJsonBody(ctx);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
          const body = asRecord(parsed.value);
          const r = mergePullIn(repo, pr, asString(body.merge_method, 'squash'));
          if (r.error) { errJson(res, r.error.status, r.error.message); return true; }
          sendJson(res, 200, { sha: r.sha, merged: true, message: `Merge pull request #${pr.number}` }, scopes);
          return true;
        }
        errJson(res, 404, 'Not Found'); return true;
      }
      errJson(res, 404, 'Not Found'); return true;
    }

    errJson(res, 404, 'Not Found'); return true;
  }

  errJson(res, 404, 'Not Found');
  return true;
}

function baseTreeOf(repo: Repo, commitOid: string): string { return store.treeAt(repo, commitOid); }

// ---------------------------------------------------------------- GraphQL

type GqlValue = null | boolean | number | string | GqlValue[] | { [k: string]: GqlValue } | { __var: string } | { __enum: string };
interface GqlField {
  alias: string | null; name: string; args: Record<string, GqlValue>; selections: GqlField[] | null;
  fragmentType: string | null; spread: string | null;
}
interface GqlOperation { kind: 'query' | 'mutation'; name: string | null; variables: Record<string, GqlValue>; selections: GqlField[]; }

function gqlTokenize(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  const isName = (c: string): boolean => /[A-Za-z0-9_]/.test(c);
  while (i < src.length) {
    const c = src[i]!;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') { i += 1; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (src.startsWith('...', i)) { tokens.push('...'); i += 3; continue; }
    if ('{}():$![]=@'.includes(c)) { tokens.push(c); i += 1; continue; }
    if (c === '"') {
      if (src.startsWith('"""', i)) {
        const end = src.indexOf('"""', i + 3);
        tokens.push(JSON.stringify(end < 0 ? src.slice(i + 3) : src.slice(i + 3, end)));
        i = end < 0 ? src.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const e = src[j + 1]!;
          out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e === 'u' ? String.fromCharCode(parseInt(src.slice(j + 2, j + 6), 16)) : e;
          j += e === 'u' ? 6 : 2;
        } else { out += src[j]; j += 1; }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c) && (c !== '-' || /[0-9]/.test(src[i + 1] ?? ''))) {
      let j = i;
      if (src[j] === '-') j += 1;
      while (j < src.length && /[0-9]/.test(src[j]!)) j += 1;
      if (src[j] === '.') { j += 1; while (j < src.length && /[0-9]/.test(src[j]!)) j += 1; }
      if (src[j] === 'e' || src[j] === 'E') { j += 1; if (src[j] === '+' || src[j] === '-') j += 1; while (j < src.length && /[0-9]/.test(src[j]!)) j += 1; }
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    if (isName(c)) {
      let j = i;
      while (j < src.length && isName(src[j]!)) j += 1;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  #toks: string[];
  #pos = 0;
  constructor(src: string) { this.#toks = gqlTokenize(src); }
  #peek(): string | undefined { return this.#toks[this.#pos]; }
  #next(): string { return this.#toks[this.#pos++]!; }
  #expect(t: string): void { const got = this.#next(); if (got !== t) throw new Error(`expected ${t}, got ${got}`); }
  parseDocument(): { operations: GqlOperation[]; fragments: Map<string, GqlField[]> } {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, GqlField[]>();
    while (this.#pos < this.#toks.length) {
      const tok = this.#peek();
      if (tok === 'fragment') {
        this.#next();
        const name = this.#next();
        this.#expect('on');
        const typeName = this.#next();
        const selections = this.#parseSelectionSet();
        fragments.set(name, selections);
        void typeName;
      } else if (tok === 'query' || tok === 'mutation' || tok === 'subscription') {
        const kind = this.#next() as 'query' | 'mutation';
        let name: string | null = null;
        if (this.#peek() && this.#peek() !== '(' && this.#peek() !== '{') name = this.#next();
        const variables = this.#parseVariableDefs();
        const selections = this.#parseSelectionSet();
        operations.push({ kind, name, variables, selections });
      } else if (tok === '{') {
        operations.push({ kind: 'query', name: null, variables: {}, selections: this.#parseSelectionSet() });
      } else {
        throw new Error(`unexpected token ${tok}`);
      }
    }
    return { operations, fragments };
  }
  #parseVariableDefs(): Record<string, GqlValue> {
    const out: Record<string, GqlValue> = {};
    if (this.#peek() !== '(') return out;
    this.#next();
    while (this.#peek() !== ')') {
      this.#expect('$');
      const name = this.#next();
      this.#expect(':');
      // skip type tokens until ',' or ')' or '=' (default)
      let depth = 0;
      while (this.#peek() !== undefined) {
        const t = this.#peek()!;
        if (depth === 0 && (t === ',' || t === ')' || t === '=')) break;
        if (t === '[') depth += 1;
        if (t === ']') depth -= 1;
        this.#next();
      }
      if (this.#peek() === '=') { this.#next(); this.#parseValue(); }
      out[name] = null;
      if (this.#peek() === ',') this.#next();
    }
    this.#expect(')');
    return out;
  }
  #parseSelectionSet(): GqlField[] {
    this.#expect('{');
    const fields: GqlField[] = [];
    while (this.#peek() !== '}') {
      if (this.#peek() === '...') {
        this.#next();
        if (this.#peek() === 'on') {
          this.#next();
          const typeName = this.#next();
          const selections = this.#parseSelectionSet();
          fields.push({ alias: null, name: '__fragment', args: {}, selections, fragmentType: typeName, spread: null });
        } else {
          const spread = this.#next();
          fields.push({ alias: null, name: '__fragment', args: {}, selections: null, fragmentType: null, spread });
        }
        continue;
      }
      let alias: string | null = null;
      let name = this.#next();
      if (this.#peek() === ':') { this.#next(); alias = name; name = this.#next(); }
      const args = this.#parseArgs();
      let selections: GqlField[] | null = null;
      if (this.#peek() === '{') selections = this.#parseSelectionSet();
      fields.push({ alias, name, args, selections, fragmentType: null, spread: null });
    }
    this.#expect('}');
    return fields;
  }
  #parseArgs(): Record<string, GqlValue> {
    const out: Record<string, GqlValue> = {};
    if (this.#peek() !== '(') return out;
    this.#next();
    while (this.#peek() !== ')') {
      const name = this.#next();
      this.#expect(':');
      out[name] = this.#parseValue();
      if (this.#peek() === ',') this.#next();
    }
    this.#expect(')');
    return out;
  }
  #parseValue(): GqlValue {
    const tok = this.#next();
    if (tok === '$') return { __var: this.#next() };
    if (tok === '[') {
      const list: GqlValue[] = [];
      while (this.#peek() !== ']') { list.push(this.#parseValue()); if (this.#peek() === ',') this.#next(); }
      this.#expect(']');
      return list;
    }
    if (tok === '{') {
      const obj: { [k: string]: GqlValue } = {};
      while (this.#peek() !== '}') {
        const k = this.#next();
        this.#expect(':');
        obj[k] = this.#parseValue();
        if (this.#peek() === ',') this.#next();
      }
      this.#expect('}');
      return obj;
    }
    if (tok.startsWith('"')) return JSON.parse(tok) as string;
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (tok === 'null') return null;
    if (/^-?[0-9]/.test(tok)) return Number(tok);
    return { __enum: tok };
  }
}

function resolveVars(value: GqlValue, vars: Record<string, unknown>): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    if ('__var' in value) return vars[(value as { __var: string }).__var] ?? null;
    if ('__enum' in value) return (value as { __enum: string }).__enum;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolveVars(v as GqlValue, vars);
    return out;
  }
  if (Array.isArray(value)) return value.map((v) => resolveVars(v, vars));
  return value;
}

const GQL_SCHEMA: Record<string, { fields: string[]; enumValues?: string[] }> = {
  Query: { fields: ['viewer', 'repository', 'node'] },
  User: { fields: ['login', 'id', 'name', 'email'] },
  Repository: { fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'] },
  Ref: { fields: ['name'] },
  Issue: { fields: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt'] },
  PullRequest: { fields: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'title', 'body'] },
  IssueConnection: { fields: ['nodes', 'pageInfo', 'totalCount'] },
  PullRequestConnection: { fields: ['nodes', 'pageInfo', 'totalCount'] },
  PullRequestFileConnection: { fields: ['nodes'] },
  PageInfo: { fields: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'] },
  SearchType: { fields: [], enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT', 'WIKI'] },
  Mutation: { fields: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'] },
  CreateIssuePayload: { fields: ['issue', 'clientMutationId'] },
  CloseIssuePayload: { fields: ['issue', 'clientMutationId'] },
  CreatePullRequestPayload: { fields: ['pullRequest', 'clientMutationId'] },
  MergePullRequestPayload: { fields: ['pullRequest', 'clientMutationId'] },
  AddCommentPayload: { fields: ['commentEdge', 'clientMutationId'] },
  IssueCommentEdge: { fields: ['node'] },
  IssueComment: { fields: ['id', 'body'] },
  __Type: { fields: ['name', 'fields', 'enumValues', 'kind'] },
  __Field: { fields: ['name', 'type', 'description'] },
};

function gid(kind: string, payload: string): string { return Buffer.from(`${kind}:${payload}`, 'utf8').toString('base64'); }
function ungid(id: string): { kind: string; payload: string } | null {
  try {
    const s = Buffer.from(id, 'base64').toString('utf8');
    const idx = s.indexOf(':');
    if (idx < 0) return null;
    return { kind: s.slice(0, idx), payload: s.slice(idx + 1) };
  } catch { return null; }
}

interface GqlCtx {
  repoById: (id: number) => Repo | undefined;
  errors: string[];
  fragments: Map<string, GqlField[]>;
}

function execSelections(fields: GqlField[], parentType: string, resolve: (field: GqlField) => unknown, ctx: GqlCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    if (f.name === '__fragment') {
      if (f.spread) {
        const frag = ctx.fragments.get(f.spread);
        if (frag) Object.assign(out, execSelections(frag, parentType, resolve, ctx));
        continue;
      }
      if (f.selections) Object.assign(out, execSelections(f.selections, parentType, resolve, ctx));
      continue;
    }
    if (f.name === '__typename') { out[f.alias ?? '__typename'] = parentType; continue; }
    const schema = GQL_SCHEMA[parentType];
    if (schema && !schema.fields.includes(f.name) && !f.name.startsWith('__')) {
      ctx.errors.push(`Cannot query field "${f.name}" on type "${parentType}".`);
      out[f.alias ?? f.name] = null;
      continue;
    }
    out[f.alias ?? f.name] = resolve(f);
  }
  return out;
}

function issueNode(repo: Repo, issue: Issue, fields: GqlField[] | null, ctx: GqlCtx): unknown {
  if (!fields) return gid('Issue', `${repo.id}:${issue.number}`);
  return execSelections(fields, 'Issue', (f) => {
    switch (f.name) {
      case 'id': return gid('Issue', `${repo.id}:${issue.number}`);
      case 'number': return issue.number;
      case 'title': return issue.title;
      case 'state': return issue.state === 'open' ? 'OPEN' : 'CLOSED';
      case 'body': return issue.body;
      case 'createdAt': return issue.createdAt;
      case 'updatedAt': return issue.updatedAt;
      default: return null;
    }
  }, ctx);
}

function pullNode(repo: Repo, pr: Pull, fields: GqlField[] | null, ctx: GqlCtx): unknown {
  if (!fields) return gid('PullRequest', `${repo.id}:${pr.number}`);
  return execSelections(fields, 'PullRequest', (f) => {
    switch (f.name) {
      case 'id': return gid('PullRequest', `${repo.id}:${pr.number}`);
      case 'number': return pr.number;
      case 'title': return pr.title;
      case 'body': return pr.body;
      case 'headRefName': return pr.head;
      case 'baseRefName': return pr.base;
      case 'mergeable': return prMergeable(repo, pr);
      case 'merged': return pr.merged;
      case 'state': return pr.merged ? 'MERGED' : (pr.state === 'open' ? 'OPEN' : 'CLOSED');
      case 'files': {
        const headTip = store.branchTip(repo, pr.head);
        const baseTip = store.branchTip(repo, pr.base);
        let diffs: FileDiff[] = [];
        if (headTip && baseTip) {
          const mb = mergeBase(headTip, baseTip, store.lookup(repo));
          const mbTree = mb ? store.treeAt(repo, mb) : baseTreeOf(repo, baseTip);
          diffs = diffTrees(repo, mbTree, store.treeAt(repo, headTip));
        }
        const nodes = diffs.map((d) => ({ path: d.filename }));
        if (!f.selections) return { nodes };
        return execSelections(f.selections, 'PullRequestFileConnection', (g) => (g.name === 'nodes' ? nodes : null), ctx);
      }
      default: return null;
    }
  }, ctx);
}

function repoNode(repo: Repo, fields: GqlField[] | null, ctx: GqlCtx): unknown {
  if (!fields) return gid('Repository', `${repo.id}`);
  return execSelections(fields, 'Repository', (f) => {
    const args = f.args;
    switch (f.name) {
      case 'id': return gid('Repository', `${repo.id}`);
      case 'databaseId': return repo.id;
      case 'name': return repo.name;
      case 'nameWithOwner': return `${repo.owner}/${repo.name}`;
      case 'owner': return f.selections ? execSelections(f.selections, 'User', (g) => (g.name === 'login' ? repo.owner : g.name === 'id' ? VIEWER.id : null), ctx) : { login: repo.owner };
      case 'defaultBranchRef': {
        const tip = store.branchTip(repo, repo.defaultBranch);
        if (!tip) return null;
        return f.selections ? execSelections(f.selections, 'Ref', (g) => (g.name === 'name' ? repo.defaultBranch : null), ctx) : { name: repo.defaultBranch };
      }
      case 'viewerPermission': return 'ADMIN';
      case 'hasIssuesEnabled': return true;
      case 'issue': {
        const vars = (f as unknown as { __vars?: Record<string, unknown> }).__vars ?? {};
        const number = Number(resolveVars(args.number as GqlValue, vars));
        const issue = repo.issues.find((i) => i.number === number);
        return issue ? issueNode(repo, issue, f.selections, ctx) : null;
      }
      case 'issues': {
        const vars = (f as unknown as { __vars?: Record<string, unknown> }).__vars ?? {};
        const first = Number(resolveVars(args.first as GqlValue, vars) ?? 10);
        const after = resolveVars(args.after as GqlValue, vars) as string | null;
        const states = resolveVars(args.states as GqlValue, vars) as string[] | null;
        const orderBy = resolveVars(args.orderBy as GqlValue, vars) as Record<string, unknown> | null;
        let list = [...repo.issues];
        if (Array.isArray(states) && states.length) list = list.filter((i) => states.includes(i.state === 'open' ? 'OPEN' : 'CLOSED'));
        if (orderBy && orderBy.field === 'CREATED_AT') {
          const dir = orderBy.direction === 'ASC' ? 1 : -1;
          list.sort((a, b) => (a.seq - b.seq) * dir);
        } else {
          list.sort((a, b) => b.seq - a.seq);
        }
        let start = 0;
        if (typeof after === 'string' && after !== '') {
          try {
            const decoded = Buffer.from(after, 'base64').toString('utf8');
            const m = /^issue:(\d+)$/.exec(decoded);
            if (m) { const idx = list.findIndex((i) => i.number === Number(m[1])); if (idx >= 0) start = idx + 1; }
          } catch { /* ignore bad cursor */ }
        }
        const pageItems = list.slice(start, start + first);
        const endCursor = pageItems.length ? Buffer.from(`issue:${pageItems[pageItems.length - 1]!.number}`, 'utf8').toString('base64') : null;
        const hasNext = start + first < list.length;
        const conn: Record<string, unknown> = {
          nodes: pageItems.map((i) => issueNode(repo, i, findField(f, 'nodes'), ctx)),
          pageInfo: { hasNextPage: hasNext, endCursor },
          totalCount: list.length,
        };
        if (!f.selections) return conn;
        return execSelections(f.selections, 'IssueConnection', (g) => {
          if (g.name === 'nodes') return conn.nodes;
          if (g.name === 'totalCount') return list.length;
          if (g.name === 'pageInfo') {
            return g.selections ? execSelections(g.selections, 'PageInfo', (h) => (h.name === 'hasNextPage' ? hasNext : h.name === 'endCursor' ? endCursor : h.name === 'hasPreviousPage' ? start > 0 : h.name === 'startCursor' ? (pageItems.length ? Buffer.from(`issue:${pageItems[0]!.number}`, 'utf8').toString('base64') : null) : null), ctx) : conn.pageInfo;
          }
          return null;
        }, ctx);
      }
      case 'pullRequests': {
        const vars = (f as unknown as { __vars?: Record<string, unknown> }).__vars ?? {};
        const first = Number(resolveVars(args.first as GqlValue, vars) ?? 10);
        const list = [...repo.pulls].sort((a, b) => b.seq - a.seq).slice(0, first);
        const conn = { nodes: list.map((p) => pullNode(repo, p, findField(f, 'nodes'), ctx)), totalCount: repo.pulls.length };
        if (!f.selections) return conn;
        return execSelections(f.selections, 'PullRequestConnection', (g) => (g.name === 'nodes' ? conn.nodes : g.name === 'totalCount' ? repo.pulls.length : null), ctx);
      }
      case 'pullRequest': {
        const vars = (f as unknown as { __vars?: Record<string, unknown> }).__vars ?? {};
        const number = Number(resolveVars(args.number as GqlValue, vars));
        const pr = repo.pulls.find((p) => p.number === number);
        return pr ? pullNode(repo, pr, f.selections, ctx) : null;
      }
      default: return null;
    }
  }, ctx);
}

function findField(field: GqlField, name: string): GqlField[] | null {
  if (!field.selections) return null;
  for (const s of field.selections) if (s.name === name) return s.selections;
  return null;
}

function attachVars(fields: GqlField[], vars: Record<string, unknown>): void {
  for (const f of fields) {
    (f as unknown as { __vars: Record<string, unknown> }).__vars = vars;
    if (f.selections) attachVars(f.selections, vars);
  }
}

function execOperationFull(op: GqlOperation, vars: Record<string, unknown>, fragments: Map<string, GqlField[]>): { data: Record<string, unknown>; errors: string[] } {
  const ctx: GqlCtx = { repoById: (id) => [...store.repos.values()].find((r) => r.id === id), errors: [], fragments };
  attachVars(op.selections, vars);
  const isMutation = op.kind === 'mutation';
  const rootType = isMutation ? 'Mutation' : 'Query';
  const data = execSelections(op.selections, rootType, (f) => {
    const args = f.args;
    const resolve = (v: GqlValue): unknown => resolveVars(v, vars);
    if (f.name === '__type') {
      const typeName = resolve(args.name) as string;
      const schema = GQL_SCHEMA[typeName];
      if (!schema) return null;
      if (!f.selections) return { name: typeName };
      return execSelections(f.selections, '__Type', (g) => {
        if (g.name === 'name') return typeName;
        if (g.name === 'kind') return typeName === 'SearchType' ? 'ENUM' : 'OBJECT';
        if (g.name === 'fields') return schema.fields.map((n) => ({ name: n }));
        if (g.name === 'enumValues') return (schema.enumValues ?? []).map((n) => ({ name: n }));
        return null;
      }, ctx);
    }
    if (!isMutation) {
      switch (f.name) {
        case 'viewer': {
          return f.selections ? execSelections(f.selections, 'User', (g) => (g.name === 'login' ? VIEWER_LOGIN : g.name === 'id' ? VIEWER.id : g.name === 'name' ? VIEWER.name : g.name === 'email' ? VIEWER.email : null), ctx) : { login: VIEWER_LOGIN };
        }
        case 'repository': {
          const owner = resolve(args.owner) as string;
          const name = resolve(args.name) as string;
          const repo = store.getRepo(owner, name);
          return repo ? repoNode(repo, f.selections, ctx) : null;
        }
        case 'node': {
          const id = resolve(args.id) as string;
          const decoded = ungid(id);
          if (!decoded) return null;
          if (decoded.kind === 'Repository') {
            const repo = ctx.repoById(Number(decoded.payload));
            if (!repo) return null;
            if (!f.selections) return { id };
            return execSelections(f.selections, 'Repository', (g) => {
              if (g.name === 'id') return id;
              if (g.name === 'name') return repo.name;
              if (g.name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
              return null;
            }, ctx);
          }
          return null;
        }
        default: return null;
      }
    }
    switch (f.name) {
      case 'createIssue': {
        const input = resolve(args.input) as Record<string, unknown>;
        const repoId = ungid(String(input.repositoryId ?? ''));
        const repo = repoId ? ctx.repoById(Number(repoId.payload)) : undefined;
        if (!repo) { ctx.errors.push('Could not resolve to a Repository with the global id.'); return null; }
        const r = createIssueIn(repo, String(input.title ?? ''), String(input.body ?? ''), []);
        if (r.error) { ctx.errors.push(r.error.message); return null; }
        const issue = r.issue!;
        if (!f.selections) return { issue: { number: issue.number, id: gid('Issue', `${repo.id}:${issue.number}`) } };
        return execSelections(f.selections, 'CreateIssuePayload', (g) => (g.name === 'issue' ? issueNode(repo, issue, g.selections, ctx) : null), ctx);
      }
      case 'closeIssue': {
        const input = resolve(args.input) as Record<string, unknown>;
        const decoded = ungid(String(input.issueId ?? ''));
        if (!decoded || decoded.kind !== 'Issue') { ctx.errors.push('Could not resolve to an Issue with the global id.'); return null; }
        const [repoIdStr, numStr] = decoded.payload.split(':');
        const repo = ctx.repoById(Number(repoIdStr));
        const issue = repo?.issues.find((i) => i.number === Number(numStr));
        if (!issue || !repo) { ctx.errors.push('Issue not found'); return null; }
        issue.state = 'closed';
        issue.updatedAt = iso(store.nowSec());
        invalidateIssueCache(repo, issue.number);
        if (!f.selections) return { issue: { number: issue.number, id: gid('Issue', `${repo.id}:${issue.number}`) } };
        return execSelections(f.selections, 'CloseIssuePayload', (g) => (g.name === 'issue' ? issueNode(repo, issue, g.selections, ctx) : null), ctx);
      }
      case 'createPullRequest': {
        const input = resolve(args.input) as Record<string, unknown>;
        const repoId = ungid(String(input.repositoryId ?? ''));
        const repo = repoId ? ctx.repoById(Number(repoId.payload)) : undefined;
        if (!repo) { ctx.errors.push('Could not resolve to a Repository with the global id.'); return null; }
        const r = createPullIn(repo, String(input.headRefName ?? ''), String(input.baseRefName ?? ''), String(input.title ?? ''), String(input.body ?? ''));
        if (r.error) { ctx.errors.push(r.error.message); return null; }
        const pr = r.pull!;
        if (!f.selections) return { pullRequest: { number: pr.number, id: gid('PullRequest', `${repo.id}:${pr.number}`) } };
        return execSelections(f.selections, 'CreatePullRequestPayload', (g) => (g.name === 'pullRequest' ? pullNode(repo, pr, g.selections, ctx) : null), ctx);
      }
      case 'mergePullRequest': {
        const input = resolve(args.input) as Record<string, unknown>;
        const decoded = ungid(String(input.pullRequestId ?? ''));
        if (!decoded || decoded.kind !== 'PullRequest') { ctx.errors.push('Could not resolve to a PullRequest with the global id.'); return null; }
        const [repoIdStr, numStr] = decoded.payload.split(':');
        const repo = ctx.repoById(Number(repoIdStr));
        const pr = repo?.pulls.find((p) => p.number === Number(numStr));
        if (!pr || !repo) { ctx.errors.push('Pull request not found'); return null; }
        const r = mergePullIn(repo, pr, String(input.mergeMethod ?? 'SQUASH'));
        if (r.error) { ctx.errors.push(r.error.message); return null; }
        if (!f.selections) return { pullRequest: { number: pr.number, merged: true } };
        return execSelections(f.selections, 'MergePullRequestPayload', (g) => (g.name === 'pullRequest' ? pullNode(repo, pr, g.selections, ctx) : null), ctx);
      }
      case 'addComment': {
        const input = resolve(args.input) as Record<string, unknown>;
        const decoded = ungid(String(input.subjectId ?? ''));
        if (!decoded || decoded.kind !== 'Issue') { ctx.errors.push('Could not resolve to an Issue with the global id.'); return null; }
        const [repoIdStr, numStr] = decoded.payload.split(':');
        const repo = ctx.repoById(Number(repoIdStr));
        const issue = repo?.issues.find((i) => i.number === Number(numStr));
        if (!issue || !repo) { ctx.errors.push('Issue not found'); return null; }
        const now = iso(store.nowSec());
        const comment: Comment = { id: store.nextCommentId++, body: String(input.body ?? ''), createdAt: now };
        repo.comments.get(issue.number)!.push(comment);
        const node = { id: gid('IssueComment', `${comment.id}`), body: comment.body };
        if (!f.selections) return { commentEdge: { node } };
        return execSelections(f.selections, 'AddCommentPayload', (g) => {
          if (g.name !== 'commentEdge') return null;
          return g.selections ? execSelections(g.selections, 'IssueCommentEdge', (h) => (h.name === 'node' ? (h.selections ? execSelections(h.selections, 'IssueComment', (k) => (k.name === 'id' ? node.id : k.name === 'body' ? node.body : null), ctx) : node) : null), ctx) : { node };
        }, ctx);
      }
      default: return null;
    }
  }, ctx);
  return { data, errors: ctx.errors };
}

function handleGraphql(ctx: Ctx): boolean {
  const { res } = ctx;
  if (ctx.method !== 'POST') { errJson(res, 404, 'Not Found'); return true; }
  if (!authed(ctx.req)) { errJson(res, 401, 'Requires authentication'); return true; }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    sendJson(res, 400, { errors: [{ message: 'Invalid JSON body' }] });
    return true;
  }
  const runOne = (doc: unknown): unknown => {
    const body = asRecord(doc);
    const query = asString(body.query);
    const variables = asRecord(body.variables);
    if (query === '') return { data: null, errors: [{ message: 'Must provide query string.' }] };
    let parsedDoc;
    try { parsedDoc = new GqlParser(query).parseDocument(); }
    catch (e) { return { data: null, errors: [{ message: `GraphQL parse error: ${e instanceof Error ? e.message : String(e)}` }] }; }
    if (parsedDoc.operations.length === 0) return { data: null, errors: [{ message: 'Must provide an operation.' }] };
    const op = parsedDoc.operations[0]!;
    const { data, errors } = execOperationFull(op, variables as Record<string, unknown>, parsedDoc.fragments);
    return errors.length ? { data, errors: errors.map((m) => ({ message: m })) } : { data };
  };
  const result = Array.isArray(parsed.value) ? (parsed.value as unknown[]).map(runOne) : runOne(parsed.value);
  sendJson(res, 200, result);
  return true;
}

// ---------------------------------------------------------------- MCP

interface McpToolDef { name: string; description: string; inputSchema: { type: string; properties: Record<string, Record<string, unknown>>; required: string[]; additionalProperties: boolean }; }
const MCP_TOOLS: McpToolDef[] = [
  { name: 'create_repo', description: 'Create a new repository for the authenticated user.', inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' } }, required: ['name'], additionalProperties: false } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'], additionalProperties: false } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Issue title' }, body: { type: 'string', description: 'Issue body' } }, required: ['owner', 'repo', 'title'], additionalProperties: false } },
  { name: 'list_issues', description: 'List issues in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Issue state: open, closed, or all', enum: ['open', 'closed', 'all'] } }, required: ['owner', 'repo'], additionalProperties: false } },
  { name: 'create_pull_request', description: 'Create a pull request in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Pull request title' }, head: { type: 'string', description: 'Head branch name' }, base: { type: 'string', description: 'Base branch name' }, body: { type: 'string', description: 'Pull request body' } }, required: ['owner', 'repo', 'title', 'head', 'base'], additionalProperties: false } },
  { name: 'merge_pull_request', description: 'Merge a pull request using squash merge.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, pull_number: { type: 'integer', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'], additionalProperties: false } },
];
const MCP_TOOLS_JSON = JSON.stringify({ tools: MCP_TOOLS });
const SERVER_NAME = 'forge';
const SERVER_VERSION = '1.0.0';

function mcpResult(res: ServerResponse, id: unknown, result: unknown, extraHeaders: Record<string, string> = {}): void {
  sendJson(res, 200, { jsonrpc: '2.0', id, result }, extraHeaders);
}
function mcpError(res: ServerResponse, id: unknown, code: number, message: string, httpStatus = 200): void {
  sendJson(res, httpStatus, { jsonrpc: '2.0', id, error: { code, message } });
}

const ARG_SYNONYMS: Record<string, string[]> = {
  owner: ['owner', 'owner_login', 'ownerLogin'],
  repo: ['repo', 'repository', 'repo_name', 'repository_name', 'name'],
  name: ['name', 'repo', 'repository_name'],
  title: ['title'],
  body: ['body', 'description'],
  head: ['head', 'head_ref', 'headRef', 'head_branch'],
  base: ['base', 'base_ref', 'baseRef', 'base_branch'],
  pull_number: ['pull_number', 'pullNumber', 'number', 'pr_number'],
  state: ['state'],
  private: ['private'],
  description: ['description'],
};
function canonicalArgs(tool: McpToolDef, raw: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const prop of Object.keys(tool.inputSchema.properties)) {
    for (const syn of ARG_SYNONYMS[prop] ?? [prop]) {
      if (raw[syn] !== undefined) { out[prop] = raw[syn]; break; }
    }
  }
  // full_name fallback: "owner/repo"
  if ((out.owner === undefined || out.repo === undefined) && typeof raw.full_name === 'string') {
    const parts = raw.full_name.split('/');
    if (parts.length === 2) { if (out.owner === undefined) out.owner = parts[0]; if (out.repo === undefined) out.repo = parts[1]; }
  }
  return out;
}

function mcpCallTool(name: string, args: Record<string, unknown>): { ok: true; value: unknown } | { ok: false; message: string } {
  const norm = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, '');
  const tool = MCP_TOOLS.find((t) => norm(t.name) === norm(name) || norm(name).endsWith(norm(t.name)));
  if (!tool) return { ok: false, message: `Unknown tool: ${name}` };
  const a = canonicalArgs(tool, args);
  for (const reqProp of tool.inputSchema.required) {
    if (a[reqProp] === undefined || a[reqProp] === null || a[reqProp] === '') return { ok: false, message: `Missing required argument: ${reqProp}` };
  }
  if (tool.name === 'create_repo') {
    const repoName = String(a.name).split('/').pop()!;
    if (store.getRepo(VIEWER_LOGIN, repoName)) return { ok: false, message: 'Repository already exists' };
    const repo = store.createRepo(repoName, Boolean(a.private), typeof a.description === 'string' ? a.description : '');
    return { ok: true, value: repoJson(repo) };
  }
  const repo = store.getRepo(String(a.owner), String(a.repo));
  if (!repo) return { ok: false, message: 'Not Found' };
  switch (tool.name) {
    case 'get_repo': return { ok: true, value: repoJson(repo) };
    case 'create_issue': {
      const r = createIssueIn(repo, String(a.title), typeof a.body === 'string' ? a.body : '', []);
      if (r.error) return { ok: false, message: r.error.message };
      return { ok: true, value: issueJson(repo, r.issue!) };
    }
    case 'list_issues': {
      const state = typeof a.state === 'string' ? a.state : 'open';
      const list = repo.issues.filter((i) => state === 'all' ? true : i.state === state).map((i) => issueJson(repo, i));
      return { ok: true, value: { issues: list } };
    }
    case 'create_pull_request': {
      const head = String(a.head).split(':').pop()!;
      const base = String(a.base).split(':').pop()!;
      const r = createPullIn(repo, head, base, String(a.title), typeof a.body === 'string' ? a.body : '');
      if (r.error) return { ok: false, message: r.error.message };
      return { ok: true, value: pullJson(repo, r.pull!) };
    }
    case 'merge_pull_request': {
      const pr = repo.pulls.find((p) => p.number === Number(a.pull_number));
      if (!pr) return { ok: false, message: 'Pull request not found' };
      const r = mergePullIn(repo, pr, 'squash');
      if (r.error) return { ok: false, message: r.error.message };
      return { ok: true, value: { merged: true, sha: r.sha, number: pr.number } };
    }
    default: return { ok: false, message: `Unknown tool: ${name}` };
  }
}

function handleMcp(ctx: Ctx): boolean {
  const { res, method } = ctx;
  if (method === 'DELETE') { sendJson(res, 204, null); return true; }
  if (method !== 'POST') { errJson(res, 405, 'Method Not Allowed'); return true; }
  let bodyJson: unknown;
  try { bodyJson = JSON.parse(ctx.body.toString('utf8')); }
  catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  const msg = asRecord(bodyJson);
  const id: unknown = msg.id ?? null;
  const hasId = msg.id !== undefined;
  if (!authed(ctx.req)) {
    sendJson(res, 401, { jsonrpc: '2.0', id, error: { code: -32000, message: 'Requires authentication' } });
    return true;
  }
  const m = asString(msg.method);
  const params = asRecord(msg.params);
  if (m.startsWith('notifications/')) { res.writeHead(202); res.end(); return true; }
  switch (m) {
    case 'server/discover': {
      mcpResult(res, id, {
        supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
        capabilities: { tools: {}, logging: {}, prompts: {}, resources: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION } },
      });
      return true;
    }
    case 'initialize': {
      const version = typeof params.protocolVersion === 'string' && params.protocolVersion !== '' ? params.protocolVersion : '2025-11-25';
      mcpResult(res, id, {
        protocolVersion: version,
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      }, { 'mcp-session-id': 'session-1' });
      return true;
    }
    case 'ping': {
      mcpResult(res, id, {});
      return true;
    }
    case 'tools/list': {
      // Byte-identical on every call: same prebuilt payload.
      const payload = `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":${MCP_TOOLS_JSON}}\n`;
      const headers: Record<string, string> = { 'x-github-request-id': reqId(), 'content-type': JSON_TYPE, 'content-length': String(Buffer.byteLength(payload)) };
      res.writeHead(200, headers);
      res.end(payload);
      return true;
    }
    case 'tools/call': {
      const toolName = asString(params.name);
      const args = asRecord(params.arguments);
      const r = mcpCallTool(toolName, args);
      if (!r.ok) {
        // Distinguish unknown tool / missing args (protocol error) from a tool failure.
        if (r.message.startsWith('Unknown tool') || r.message.startsWith('Missing required argument')) {
          mcpError(res, id, -32602, r.message);
        } else {
          mcpResult(res, id, { content: [{ type: 'text', text: JSON.stringify({ error: r.message }) }], structuredContent: { error: r.message }, isError: true });
        }
        return true;
      }
      const text = JSON.stringify(r.value);
      mcpResult(res, id, { content: [{ type: 'text', text }], structuredContent: r.value });
      return true;
    }
    default: {
      if (!hasId) { res.writeHead(202); res.end(); return true; }
      mcpError(res, id, -32601, `Method not found: ${m}`);
      return true;
    }
  }
}

// ---------------------------------------------------------------- git smart HTTP

function allRefsSorted(repo: Repo): { ref: string; oid: string }[] {
  return [...repo.refs.entries()].map(([ref, oid]) => ({ ref, oid })).sort((a, b) => (a.ref < b.ref ? -1 : 1));
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const parts: Buffer[] = [];
  parts.push(pktLine(`# service=${service}\n`));
  parts.push(pktFlush());
  const caps = service === 'git-upload-pack'
    ? `symref=HEAD:refs/heads/${repo.defaultBranch} side-band-64k shallow thin-pack ofs-delta agent=forge/1.0 multi_ack`
    : 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0';
  const tip = store.branchTip(repo, repo.defaultBranch);
  const refs = allRefsSorted(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const headOid = tip ?? ZERO_OID;
    parts.push(pktLine(`${headOid} HEAD\0${caps}\n`));
    for (const { ref, oid } of refs) {
      parts.push(pktLine(`${oid} ${ref}\n`));
      if (ref.startsWith('refs/tags/')) {
        const obj = repo.objects.get(oid);
        if (obj && obj.type === 'tag') {
          const target = parseTag(obj.data).object;
          parts.push(pktLine(`${target} ${ref}^{}\n`));
        }
      }
    }
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

function v2Advertisement(): Buffer {
  const parts: Buffer[] = [];
  parts.push(pktLine('version 2\n'));
  parts.push(pktLine('agent=forge/1.0\n'));
  parts.push(pktLine('ls-refs=unborn\n'));
  parts.push(pktLine('fetch=shallow filter\n'));
  parts.push(pktLine('object-format=sha1\n'));
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

interface FetchPlan {
  objects: Map<string, GitObject>;
  shallow: string[];
  unshallow: string[];
}

/** Compute the pack + shallow lines for a fetch. wants/haves are commit oids (tags resolved by caller). */
function planFetch(repo: Repo, wants: string[], haves: string[], depth: number | undefined, shallowInput: string[]): FetchPlan {
  const lookup = store.lookup(repo);
  // Resolve wants to commits (tag objects are included verbatim).
  const wantCommits: string[] = [];
  const extraObjects = new Set<string>();
  for (const w of wants) {
    const obj = repo.objects.get(w);
    if (!obj) continue;
    if (obj.type === 'tag') {
      extraObjects.add(w);
      const target = parseTag(obj.data).object;
      const tObj = repo.objects.get(target);
      if (tObj && tObj.type === 'commit') wantCommits.push(target);
    } else if (obj.type === 'commit') {
      wantCommits.push(w);
    }
  }
  const haveReachable = haves.length ? collectReachable(haves, lookup, true) : new Set<string>();
  const shallowSet = new Set(shallowInput);
  let objects = new Set<string>();
  let shallow: string[] = [];
  let unshallow: string[] = [];
  if (depth !== undefined) {
    // BFS by generation from wants.
    const included = new Set<string>();
    const level = new Map<string, number>();
    const queue: string[] = [];
    for (const w of wantCommits) { if (!included.has(w)) { included.add(w); level.set(w, 0); queue.push(w); } }
    while (queue.length) {
      const oid = queue.shift()!;
      const lv = level.get(oid)!;
      // Depth d includes generations 0..d-1 only: a parent at level lv+1 is
      // included only when lv+1 < d (depth 1 = the tip commit alone).
      if (lv + 1 >= depth) continue;
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const p of parseCommit(obj.data).parents) {
        if (!included.has(p)) { included.add(p); level.set(p, lv + 1); queue.push(p); }
      }
    }
    // Objects reachable from included commits without following parents past the depth limit.
    const toSend = new Set<string>();
    for (const oid of included) {
      const lv = level.get(oid)!;
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      toSend.add(oid);
      const treeOid = parseCommit(obj.data).tree;
      // Add the tree and blobs; for commits at max depth, do not follow parents.
      const treeSet = collectReachable([treeOid], lookup, true);
      for (const o of treeSet) toSend.add(o);
      if (lv < depth) {
        // parents are included, nothing extra needed (they are visited themselves)
      }
    }
    for (const e of extraObjects) toSend.add(e);
    // Subtract only what the client provably has: each have's own snapshot
    // (the have commit plus its tree). Do NOT subtract everything reachable
    // from the haves — in a shallow clone the have's ancestors are exactly
    // what a deepen is asking for, and reachable() follows parents.
    for (const h of haves) {
      const obj = repo.objects.get(h);
      if (!obj) continue;
      toSend.delete(h);
      if (obj.type === 'commit') {
        for (const o of collectReachable([parseCommit(obj.data).tree], lookup, true)) toSend.delete(o);
      } else if (obj.type === 'tag') {
        const target = parseTag(obj.data).object;
        const tObj = repo.objects.get(target);
        if (tObj && tObj.type === 'commit') {
          toSend.delete(target);
          for (const o of collectReachable([parseCommit(tObj.data).tree], lookup, true)) toSend.delete(o);
        }
      }
    }
    objects = toSend;
    const boundary = new Set<string>();
    for (const oid of included) {
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      const parents = parseCommit(obj.data).parents;
      if (parents.length > 0 && parents.some((p) => !included.has(p))) boundary.add(oid);
    }
    shallow = [...boundary].sort();
    for (const s of shallowInput) {
      if (included.has(s) && !boundary.has(s)) unshallow.push(s);
    }
    unshallow.sort();
  } else {
    const wantReachable = collectReachable(wantCommits, lookup, true);
    for (const e of extraObjects) wantReachable.add(e);
    for (const h of haveReachable) wantReachable.delete(h);
    objects = wantReachable;
  }
  const objMap = new Map<string, GitObject>();
  for (const oid of objects) {
    const obj = repo.objects.get(oid);
    if (obj) objMap.set(oid, obj);
  }
  return { objects: objMap, shallow, unshallow };
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let off = 0; off < pack.length; off += 32768) {
    const chunk = pack.subarray(off, Math.min(off + 32768, pack.length));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  return Buffer.concat(parts);
}

function handleUploadPack(ctx: Ctx, repo: Repo): void {
  const { res } = ctx;
  const isV2 = (ctx.req.headers['git-protocol'] ?? '') === 'version=2';
  const body = ctx.body;
  try {
    const pkts = decodePktLines(body);
    const firstData = pkts.find((p) => p.kind === 'data');
    const firstLine = firstData ? firstData.payload.toString('utf8').trim() : '';
    if (isV2 || firstLine.startsWith('command=')) {
      // v2
      let command = '';
      const args: string[] = [];
      let afterDelim = false;
      for (const p of pkts) {
        if (p.kind === 'delim') { afterDelim = true; continue; }
        if (p.kind !== 'data') continue;
        const line = p.payload.toString('utf8').replace(/\n$/, '');
        if (line.startsWith('command=')) command = line.slice('command='.length).trim();
        else if (afterDelim || !line.startsWith('command=')) args.push(line);
      }
      if (command === 'ls-refs') {
        const peel = args.includes('peel');
        const symrefs = args.includes('symrefs');
        const unborn = args.includes('unborn');
        const prefixes = args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice('ref-prefix '.length));
        const parts: Buffer[] = [];
        const refs = allRefsSorted(repo);
        const tip = store.branchTip(repo, repo.defaultBranch);
        if (prefixes.length === 0) {
          if (tip) {
            const extra = symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : '';
            parts.push(pktLine(`${tip} HEAD${extra}\n`));
          } else if (unborn) {
            parts.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
          }
        }
        for (const { ref, oid } of refs) {
          if (prefixes.length && !prefixes.some((p) => ref.startsWith(p))) continue;
          let line = `${oid} ${ref}`;
          if (symrefs && ref === `refs/heads/${repo.defaultBranch}`) line += ` symref-target:refs/heads/${repo.defaultBranch}`;
          if (peel && ref.startsWith('refs/tags/')) {
            const obj = repo.objects.get(oid);
            if (obj && obj.type === 'tag') line += ` peeled:${parseTag(obj.data).object}`;
          }
          parts.push(pktLine(`${line}\n`));
        }
        parts.push(pktFlush());
        sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
        return;
      }
      if (command === 'fetch') {
        const wants: string[] = [];
        const haves: string[] = [];
        const shallowIn: string[] = [];
        let depth: number | undefined;
        for (const a of args) {
          if (a.startsWith('want ')) wants.push(a.slice(5).trim());
          else if (a.startsWith('have ')) haves.push(a.slice(5).trim());
          else if (a.startsWith('shallow ')) shallowIn.push(a.slice(8).trim());
          else if (a.startsWith('deepen ')) { const n = parseInt(a.slice(7).trim(), 10); if (Number.isFinite(n)) depth = n; }
        }
        const plan = planFetch(repo, wants, haves, depth, shallowIn);
        const pack = writePack(plan.objects.values());
        const parts: Buffer[] = [];
        parts.push(pktLine('acknowledgments\n'));
        if (haves.length) parts.push(pktLine('NAK\n'));
        parts.push(pktDelim());
        if (plan.shallow.length || plan.unshallow.length) {
          parts.push(pktLine('shallow-info\n'));
          for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
          for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
          parts.push(pktDelim());
        }
        parts.push(pktLine('packfile\n'));
        parts.push(sidebandPack(pack));
        parts.push(pktFlush());
        sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
        return;
      }
      sendRaw(res, 200, pktFlush(), 'application/x-git-upload-pack-result');
      return;
    }
    // v0 fetch
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowIn: string[] = [];
    let depth: number | undefined;
    let seenFlush = false;
    for (const p of pkts) {
      if (p.kind === 'flush') { seenFlush = true; continue; }
      if (p.kind !== 'data') continue;
      const line = p.payload.toString('utf8').replace(/\n$/, '');
      if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0]!.trim());
      else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) shallowIn.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) { const n = parseInt(line.slice(7).trim(), 10); if (Number.isFinite(n)) depth = n; }
      void seenFlush;
    }
    const plan = planFetch(repo, wants, haves, depth, shallowIn);
    const pack = writePack(plan.objects.values());
    const parts: Buffer[] = [];
    if (haves.length) parts.push(pktLine('NAK\n'));
    for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(sidebandPack(pack));
    parts.push(pktFlush());
    sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
  } catch {
    // Malformed body: stay alive, answer with an empty pack result.
    sendRaw(res, 200, pktFlush(), 'application/x-git-upload-pack-result');
  }
}

function handleReceivePack(ctx: Ctx, repo: Repo): void {
  const { res } = ctx;
  const body = ctx.body;
  try {
    const pkts = decodePktLines(body);
    // Find the first flush: everything after it is the pack.
    let flushIdx = -1;
    for (let i = 0; i < pkts.length; i += 1) if (pkts[i]!.kind === 'flush') { flushIdx = i; break; }
    if (flushIdx < 0) {
      sendRaw(res, 200, pktLine('unpack ok\n'), 'application/x-git-receive-pack-result');
      return;
    }
    // Recompute the byte offset of the pack: re-encode consumed pkt-lines.
    let offset = 0;
    for (let i = 0; i <= flushIdx; i += 1) {
      const p = pkts[i]!;
      if (p.kind === 'flush' || p.kind === 'delim' || p.kind === 'response-end') offset += 4;
      else offset += 4 + p.payload.length;
    }
    interface Cmd { oldOid: string; newOid: string; ref: string; }
    const cmds: Cmd[] = [];
    let sideBand = false;
    for (let i = 0; i < flushIdx; i += 1) {
      const p = pkts[i]!;
      if (p.kind !== 'data') continue;
      let text = p.payload.toString('utf8');
      const nul = text.indexOf('\0');
      if (nul >= 0) {
        const caps = text.slice(nul + 1);
        if (caps.includes('side-band-64k')) sideBand = true;
        text = text.slice(0, nul);
      }
      const parts = text.trim().split(' ');
      if (parts.length >= 3) cmds.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: parts[2]! });
    }
    const packBytes = body.subarray(offset);
    let unpackOk = true;
    if (packBytes.length > 0) {
      try {
        if (!verifyPackChecksum(packBytes)) throw new Error('pack checksum mismatch');
        const { objects } = readPack(packBytes, (oid) => repo.objects.get(oid));
        for (const [oid, obj] of objects) if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      } catch {
        unpackOk = false;
      }
    }
    const inner: Buffer[] = [];
    inner.push(pktLine(unpackOk ? 'unpack ok\n' : 'unpack error\n'));
    if (unpackOk) {
      for (const c of cmds) {
        const current = repo.refs.get(c.ref) ?? ZERO_OID;
        let ok = false;
        let reason = 'non-fast-forward';
        if (c.newOid === ZERO_OID) {
          // delete
          if (current !== ZERO_OID) { repo.refs.delete(c.ref); ok = true; }
          else reason = 'ref does not exist';
        } else if (!repo.objects.has(c.newOid)) {
          reason = 'missing object';
        } else if (c.oldOid === ZERO_OID) {
          if (current === ZERO_OID) { repo.refs.set(c.ref, c.newOid); ok = true; }
        } else if (current !== c.oldOid) {
          reason = 'non-fast-forward';
        } else if (c.ref.startsWith('refs/tags/')) {
          repo.refs.set(c.ref, c.newOid); ok = true;
        } else if (isAncestor(c.oldOid, c.newOid, store.lookup(repo))) {
          repo.refs.set(c.ref, c.newOid); ok = true;
        }
        inner.push(pktLine(ok ? `ok ${c.ref}\n` : `ng ${c.ref} ${reason}\n`));
      }
    } else {
      for (const c of cmds) inner.push(pktLine(`ng ${c.ref} unpack failed\n`));
    }
    const innerBytes = Buffer.concat(inner);
    let out: Buffer;
    if (sideBand) {
      const parts: Buffer[] = [];
      for (let off = 0; off < innerBytes.length; off += 32768) {
        const chunk = innerBytes.subarray(off, Math.min(off + 32768, innerBytes.length));
        parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
      }
      parts.push(pktFlush());
      out = Buffer.concat(parts);
    } else {
      out = Buffer.concat([innerBytes, pktFlush()]);
    }
    sendRaw(res, 200, out, 'application/x-git-receive-pack-result');
  } catch {
    sendRaw(res, 200, pktLine('unpack ok\n'), 'application/x-git-receive-pack-result');
  }
}

function handleGit(ctx: Ctx): boolean {
  const { res, method, segs } = ctx;
  // /{owner}/{repo}.git/...
  if (segs.length < 2 || !segs[1]!.endsWith('.git')) return false;
  const owner = segs[0]!;
  const name = segs[1]!.slice(0, -4);
  const repo = store.getRepo(owner, name);
  if (!authed(ctx.req)) { errJson(res, 401, 'Requires authentication'); return true; }
  if (!repo) { errJson(res, 404, 'Not Found'); return true; }
  const tail = segs.slice(2);
  if (method === 'GET' && tail[0] === 'info' && tail[1] === 'refs') {
    const service = ctx.query.get('service') ?? '';
    if (service === 'git-upload-pack') {
      if ((ctx.req.headers['git-protocol'] ?? '') === 'version=2') {
        sendRaw(res, 200, v2Advertisement(), 'application/x-git-upload-pack-advertisement');
      } else {
        sendRaw(res, 200, v0Advertisement(repo, 'git-upload-pack'), 'application/x-git-upload-pack-advertisement');
      }
      return true;
    }
    if (service === 'git-receive-pack') {
      sendRaw(res, 200, v0Advertisement(repo, 'git-receive-pack'), 'application/x-git-receive-pack-advertisement');
      return true;
    }
    errJson(res, 400, 'Missing service parameter');
    return true;
  }
  if (method === 'POST' && tail[0] === 'git-upload-pack') { handleUploadPack(ctx, repo); return true; }
  if (method === 'POST' && tail[0] === 'git-receive-pack') { handleReceivePack(ctx, repo); return true; }
  errJson(res, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------- server

export function createApp(): Server {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const { segs, query } = pathSegs(req.url ?? '/');
      const ctx: Ctx = {
        req, res, method: req.method ?? 'GET', segs, query, body,
        host: req.headers.host ?? 'localhost',
      };
      try {
        // healthz (no auth)
        if (segs.length === 1 && segs[0] === 'healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (segs[0] === 'api' && segs[1] === 'v3') { void handleRest(ctx); return; }
        if (segs[0] === 'api' && segs[1] === 'graphql') { handleGraphql(ctx); return; }
        if (segs[0] === 'mcp') { handleMcp(ctx); return; }
        if (handleGit(ctx)) return;
        errJson(res, 404, 'Not Found');
      } catch (e) {
        try { errJson(res, 500, e instanceof Error ? e.message : 'Internal Server Error'); } catch { /* socket closed */ }
      }
    });
    req.on('error', () => { try { res.destroy(); } catch { /* ignore */ } });
  });
  return server;
}
