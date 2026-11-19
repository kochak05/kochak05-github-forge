// A GitHub-compatible git forge: REST v3, GraphQL v4, MCP over streamable HTTP and git
// smart HTTP, all in memory, Node standard library only.
//
// The server is one process with one in-memory store. Repositories live under the token
// owner's login; every API call carries `Authorization: Bearer $MAKEFUN_SHOP_TOKEN` and
// /healthz is the only route that takes none. Git objects are stored exactly as pushed:
// the pack reader keeps raw object bytes, so a clone re-serves byte-identical objects.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const VIEWER_ID = 1000;
const ZERO_OID = '0000000000000000000000000000000000000000';
const DEFAULT_BRANCH = 'main';
const JSON_TYPE = 'application/json; charset=utf-8';
const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const SERVER_NAME = 'makefun-github-core-clone';
const SERVER_VERSION = '1.0.0';

// -------------------------------------------------------------------------------------------
// Small utilities
// -------------------------------------------------------------------------------------------

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

/** The git id of an object: SHA-1 over `<type> <size>\0` + bytes. */
function hashObject(type: string, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}

function b64encode(data: Buffer | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}

function b64urlEncode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}

function b64urlDecode(text: string): string {
  return Buffer.from(text, 'base64url').toString('utf8');
}

function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function nowIso(): string {
  return new Date().toISOString();
}

function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

function requestId(): string {
  return randomBytes(8).toString('hex');
}

// -------------------------------------------------------------------------------------------
// pkt-lines (git's framing: 4 hex length digits, then the payload; 0000 flush, 0001 delim)
// -------------------------------------------------------------------------------------------

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const length = body.length + 4;
  const head = Buffer.from(length.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type PktKind = 'data' | 'flush' | 'delim';
interface Pkt {
  kind: PktKind;
  payload: Buffer;
}

/**
 * Decode pkt-lines from the front of `buf`. Returns the packets and the offset just past
 * the last complete packet (a caller that expects a pack after the flush reads from there).
 * Throws on a malformed length prefix.
 */
function parsePktLines(buf: Buffer): { packets: Pkt[]; offset: number } {
  const packets: Pkt[] = [];
  let offset = 0;
  while (offset < buf.length) {
    if (offset + 4 > buf.length) throw new Error('pkt-line truncated');
    const head = buf.subarray(offset, offset + 4).toString('ascii');
    if (head === '0000') {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (head === '0001') {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`bad pkt-line length ${JSON.stringify(head)}`);
    const length = parseInt(head, 16);
    if (length < 4 || offset + length > buf.length) throw new Error('pkt-line length out of range');
    packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return { packets, offset };
}

/** The data payloads of a pkt-line body, as text lines without their trailing newline. */
function pktTextLines(buf: Buffer): string[] {
  const { packets } = parsePktLines(buf);
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    lines.push(packet.payload.toString('utf8').replace(/\n$/, ''));
  }
  return lines;
}

// -------------------------------------------------------------------------------------------
// Git objects: trees, commits, tags, and the flat file maps built on top of them
// -------------------------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: ObjType;
  data: Buffer;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

/** Parse a tree object's entries: `<mode> <name>\0<20-byte oid>` repeated. */
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) break;
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const mode = data.subarray(offset, space).toString('ascii');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

/** Git's tree sort: entries compare by name, with directories compared as if ending in '/'. */
function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const ka = treeSortKey(a);
    const kb = treeSortKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

/** Split a commit object into its headers and its message. */
function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  const view: CommitView = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of head.split('\n')) {
    const space = line.indexOf(' ');
    if (space < 0) continue;
    const key = line.slice(0, space);
    const value = line.slice(space + 1);
    if (key === 'tree') view.tree = value;
    else if (key === 'parent') view.parents.push(value);
    else if (key === 'author') view.author = value;
    else if (key === 'committer') view.committer = value;
  }
  return view;
}

function buildCommit(view: CommitView): Buffer {
  const lines: string[] = [`tree ${view.tree}`];
  for (const parent of view.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${view.author}`, `committer ${view.committer}`, '');
  const message = view.message.endsWith('\n') || view.message === '' ? view.message : `${view.message}\n`;
  // The joined headers end with a single newline (from the trailing empty line);
  // one more newline makes the blank line that separates headers from the message.
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  const view: TagView = { object: '', type: '', tag: '', tagger: '', message };
  for (const line of head.split('\n')) {
    const space = line.indexOf(' ');
    if (space < 0) continue;
    const key = line.slice(0, space);
    const value = line.slice(space + 1);
    if (key === 'object') view.object = value;
    else if (key === 'type') view.type = value;
    else if (key === 'tag') view.tag = value;
    else if (key === 'tagger') view.tagger = value;
  }
  return view;
}

function buildTag(view: TagView): Buffer {
  const lines = [`object ${view.object}`, `type ${view.type}`, `tag ${view.tag}`, `tagger ${view.tagger}`, ''];
  const message = view.message.endsWith('\n') || view.message === '' ? view.message : `${view.message}\n`;
  // Same blank-line separator between headers and message as a commit object.
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

/** `Name <email> <unix> +0000`, the identity line commits and tags carry. */
function identLine(timestamp: number): string {
  return `${VIEWER_LOGIN} <${VIEWER_EMAIL}> ${timestamp} +0000`;
}

// A flat file map: path -> blob oid + mode. Trees are built from it and read back into it.
type FileMap = Map<string, { oid: string; mode: string }>;

/** Walk a tree object recursively into a flat path map. */
function flattenTree(objects: Map<string, GitObject>, treeOid: string, prefix: string, out: FileMap): void {
  const tree = objects.get(treeOid);
  if (tree === undefined || tree.type !== 'tree') return;
  for (const entry of parseTree(tree.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(objects, entry.oid, path, out);
    else out.set(path, { oid: entry.oid, mode: entry.mode });
  }
}

/** Build (and store) the tree objects for a flat file map; answers the root tree oid. */
function buildTreeFromMap(objects: Map<string, GitObject>, files: FileMap): string {
  const store = (type: ObjType, data: Buffer): string => {
    const oid = hashObject(type, data);
    if (!objects.has(oid)) objects.set(oid, { type, data });
    return oid;
  };
  const buildDir = (prefix: string): string => {
    const entries: TreeEntry[] = [];
    const subdirs = new Set<string>();
    for (const [path, file] of files) {
      if (prefix !== '' && !path.startsWith(`${prefix}/`)) continue;
      const rest = prefix === '' ? path : path.slice(prefix.length + 1);
      const slash = rest.indexOf('/');
      if (slash < 0) entries.push({ mode: file.mode, name: rest, oid: file.oid });
      else subdirs.add(rest.slice(0, slash));
    }
    for (const dir of [...subdirs].sort()) {
      const childPrefix = prefix === '' ? dir : `${prefix}/${dir}`;
      entries.push({ mode: '40000', name: dir, oid: buildDir(childPrefix) });
    }
    return store('tree', buildTree(entries));
  };
  return buildDir('');
}

/** Store an object if absent; answers its oid. */
function storeObject(objects: Map<string, GitObject>, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!objects.has(oid)) objects.set(oid, { type, data });
  return oid;
}

/** Follow annotated tags to the object they point at. */
function peelTo(objects: Map<string, GitObject>, oid: string): string {
  let current = oid;
  for (let hops = 0; hops < 10; hops += 1) {
    const object = objects.get(current);
    if (object === undefined || object.type !== 'tag') return current;
    current = parseTag(object.data).object;
  }
  return current;
}

/** Every commit reachable from `tips`, following parents (tags peeled first). */
function reachableCommits(objects: Map<string, GitObject>, tips: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = tips.map((tip) => peelTo(objects, tip));
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const object = objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    seen.add(oid);
    for (const parent of parseCommit(object.data).parents) stack.push(parent);
  }
  return seen;
}

/** Every object reachable from `tips`: commits, their trees and blobs, tags on the way. */
function reachableObjects(objects: Map<string, GitObject>, tips: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const visitObject = (oid: string): void => {
    if (seen.has(oid)) return;
    const object = objects.get(oid);
    if (object === undefined) return;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      visitObject(commit.tree);
      for (const parent of commit.parents) visitObject(parent);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) visitObject(entry.oid);
    } else if (object.type === 'tag') {
      visitObject(parseTag(object.data).object);
    }
  };
  for (const tip of tips) visitObject(tip);
  return seen;
}

/** Whether `ancestor` is reachable from `tip` (or is the tip itself). */
function isAncestor(objects: Map<string, GitObject>, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  return reachableCommits(objects, [tip]).has(ancestor);
}

/** Count added/removed lines between two texts with a small longest-common-subsequence diff. */
function lineDiffCounts(oldText: string, newText: string): { additions: number; deletions: number } {
  const oldLines = oldText === '' ? [] : oldText.split('\n');
  const newLines = newText === '' ? [] : newText.split('\n');
  if (oldLines.length * newLines.length > 1_000_000) {
    return { additions: newLines.length, deletions: oldLines.length };
  }
  const width = newLines.length + 1;
  const table = new Uint32Array((oldLines.length + 1) * width);
  for (let i = oldLines.length - 1; i >= 0; i -= 1) {
    for (let j = newLines.length - 1; j >= 0; j -= 1) {
      table[i * width + j] =
        oldLines[i] === newLines[j]
          ? table[(i + 1) * width + j + 1] + 1
          : Math.max(table[(i + 1) * width + j], table[i * width + j + 1]);
    }
  }
  let additions = 0;
  let deletions = 0;
  let i = 0;
  let j = 0;
  while (i < oldLines.length && j < newLines.length) {
    if (oldLines[i] === newLines[j]) {
      i += 1;
      j += 1;
    } else if (table[(i + 1) * width + j] >= table[i * width + j + 1]) {
      deletions += 1;
      i += 1;
    } else {
      additions += 1;
      j += 1;
    }
  }
  deletions += oldLines.length - i;
  additions += newLines.length - j;
  return { additions, deletions };
}

// -------------------------------------------------------------------------------------------
// Packs: `PACK` v2, full objects only on the way out, deltas resolved on the way in
// -------------------------------------------------------------------------------------------

const PACK_TYPE_COMMIT = 1;
const PACK_TYPE_TREE = 2;
const PACK_TYPE_BLOB = 3;
const PACK_TYPE_TAG = 4;
const PACK_TYPE_OFS_DELTA = 6;
const PACK_TYPE_REF_DELTA = 7;

const PACK_TYPE_NAMES: Record<number, ObjType> = {
  [PACK_TYPE_COMMIT]: 'commit',
  [PACK_TYPE_TREE]: 'tree',
  [PACK_TYPE_BLOB]: 'blob',
  [PACK_TYPE_TAG]: 'tag',
};

function packTypeCode(type: ObjType): number {
  return type === 'commit' ? PACK_TYPE_COMMIT : type === 'tree' ? PACK_TYPE_TREE : type === 'blob' ? PACK_TYPE_BLOB : PACK_TYPE_TAG;
}

/** A pack entry's type/size varint header. */
function packObjectHeader(type: number, size: number): Buffer {
  const bytes: number[] = [];
  let remaining = size;
  bytes.push((type << 4) | (remaining & 0x0f));
  remaining >>= 4;
  while (remaining > 0) {
    bytes[0] |= 0x80;
    bytes.push(remaining & 0x7f);
    remaining >>= 7;
  }
  // Continuation bits: every byte but the last carries 0x80.
  for (let i = 1; i < bytes.length - 1; i += 1) bytes[i] |= 0x80;
  return Buffer.from(bytes);
}

/** Read a pack entry header at `offset`: type, size and the offset of the entry body. */
function readPackObjectHeader(buf: Buffer, offset: number): { type: number; size: number; next: number } {
  const first = buf[offset] as number;
  const type = (first >> 4) & 0x07;
  let size = first & 0x0f;
  let shift = 4;
  let at = offset + 1;
  let byte = first;
  while ((byte & 0x80) !== 0) {
    byte = buf[at] as number;
    size |= (byte & 0x7f) << shift;
    shift += 7;
    at += 1;
  }
  return { type, size, next: at };
}

/** Inflate the deflate stream starting at `offset`; binary-search its exact end. */
function inflateAt(buf: Buffer, offset: number, expectedSize: number): { data: Buffer; next: number } {
  let low = offset;
  let high = buf.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    try {
      const out = inflateSync(buf.subarray(offset, mid));
      if (out.length === expectedSize) high = mid;
      else low = mid + 1;
    } catch {
      low = mid + 1;
    }
  }
  const data = inflateSync(buf.subarray(offset, low));
  if (data.length !== expectedSize) throw new Error(`pack entry inflated to ${data.length} bytes, expected ${expectedSize}`);
  return { data, next: low };
}

/** Apply a git delta to its base bytes. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let at = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[at] as number;
      at += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) return value;
    }
  };
  const baseSize = readVarint();
  const resultSize = readVarint();
  if (baseSize !== base.length) throw new Error('delta base size mismatch');
  const chunks: Buffer[] = [];
  let written = 0;
  while (at < delta.length) {
    const op = delta[at] as number;
    at += 1;
    if ((op & 0x80) !== 0) {
      let offset = 0;
      let size = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          offset |= (delta[at] as number) << (bit * 8);
          at += 1;
        }
      }
      for (let bit = 0; bit < 3; bit += 1) {
        if ((op & (0x10 << bit)) !== 0) {
          size |= (delta[at] as number) << (bit * 8);
          at += 1;
        }
      }
      if (size === 0) size = 0x10000;
      chunks.push(base.subarray(offset, offset + size));
      written += size;
    } else if (op !== 0) {
      chunks.push(delta.subarray(at, at + op));
      at += op;
      written += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== resultSize) throw new Error('delta result size mismatch');
  return Buffer.concat(chunks);
}

/**
 * Read every object out of a pack. Deltas resolve against earlier pack entries first,
 * then against `lookup` (the receiving repository's store). Answers objects by their
 * recomputed ids, exactly as the pack's bytes hash.
 */
function readPack(buf: Buffer, lookup: (oid: string) => GitObject | undefined): Map<string, GitObject> {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a pack');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const byOffset = new Map<number, GitObject>();
  const out = new Map<string, GitObject>();
  let offset = 12;
  interface PendingDelta {
    baseOid: string | null;
    baseOffset: number | null;
    data: Buffer;
    offset: number;
  }
  const pending: PendingDelta[] = [];
  const addObject = (entryOffset: number, type: ObjType, data: Buffer): void => {
    const oid = hashObject(type, data);
    const object: GitObject = { type, data };
    byOffset.set(entryOffset, object);
    out.set(oid, object);
  };
  for (let index = 0; index < count; index += 1) {
    const entryOffset = offset;
    const header = readPackObjectHeader(buf, offset);
    offset = header.next;
    if (header.type === PACK_TYPE_OFS_DELTA) {
      // The base offset is a variable-length negative offset from this entry's start.
      let byte = buf[offset] as number;
      offset += 1;
      let baseOffset = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        byte = buf[offset] as number;
        offset += 1;
        baseOffset = ((baseOffset + 1) << 7) | (byte & 0x7f);
      }
      const inflated = inflateAt(buf, offset, header.size);
      offset = inflated.next;
      pending.push({ baseOid: null, baseOffset: entryOffset - baseOffset, data: inflated.data, offset: entryOffset });
    } else if (header.type === PACK_TYPE_REF_DELTA) {
      const baseOid = buf.subarray(offset, offset + 20).toString('hex');
      offset += 20;
      const inflated = inflateAt(buf, offset, header.size);
      offset = inflated.next;
      pending.push({ baseOid, baseOffset: null, data: inflated.data, offset: entryOffset });
    } else {
      const type = PACK_TYPE_NAMES[header.type];
      if (type === undefined) throw new Error(`unknown pack object type ${header.type}`);
      const inflated = inflateAt(buf, offset, header.size);
      offset = inflated.next;
      addObject(entryOffset, type, inflated.data);
    }
  }
  for (const delta of pending) {
    let base: GitObject | undefined;
    if (delta.baseOffset !== null) base = byOffset.get(delta.baseOffset);
    else if (delta.baseOid !== null) base = out.get(delta.baseOid) ?? lookup(delta.baseOid);
    if (base === undefined) throw new Error('delta base not found');
    const resolved = applyDelta(base.data, delta.data);
    const oid = hashObject(base.type, resolved);
    const object: GitObject = { type: base.type, data: resolved };
    byOffset.set(delta.offset, object);
    out.set(oid, object);
  }
  const trailer = buf.subarray(buf.length - 20);
  const expected = sha1Hex(buf.subarray(0, buf.length - 20));
  if (trailer.toString('hex') !== expected) throw new Error('pack trailer checksum mismatch');
  return out;
}

/** Write a pack (version 2, no deltas) holding `objects` in the given order. */
function writePack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(packObjectHeader(packTypeCode(object.type), object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  const trailer = Buffer.from(sha1Hex(body), 'hex');
  return Buffer.concat([body, trailer]);
}

/** Split a buffer into sideband band-1 pkt-lines (data chunks of at most 32 KiB). */
function sidebandPackets(data: Buffer): Buffer[] {
  const packets: Buffer[] = [];
  const chunkSize = 32768;
  for (let at = 0; at < data.length; at += chunkSize) {
    const chunk = data.subarray(at, Math.min(data.length, at + chunkSize));
    packets.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  if (packets.length === 0) packets.push(pktLine(Buffer.from([1])));
  return packets;
}

// -------------------------------------------------------------------------------------------
// The store: repositories, issues, comments, labels and pull requests, all in memory
// -------------------------------------------------------------------------------------------

interface Label {
  name: string;
  color: string;
  description: string;
}

interface IssueComment {
  id: number;
  body: string;
  createdAt: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
  comments: IssueComment[];
}

interface PullRequest {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
  createdSeq: number;
  createdAt: string;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  issues: Issue[];
  pulls: PullRequest[];
  labels: Label[];
  nextNumber: number;
  nextCommentId: number;
}

const store = {
  repos: new Map<string, Repo>(),
  nextRepoId: 1,
  nextIssueId: 1,
  nextPullId: 1,
  seq: 1,
};

function findRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER_LOGIN) return undefined;
  return store.repos.get(name);
}

function createRepoRecord(name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: store.nextRepoId,
    name,
    owner: VIEWER_LOGIN,
    description,
    isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    createdSeq: store.seq,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    refs: new Map(),
    objects: new Map(),
    issues: [],
    pulls: [],
    labels: [],
    nextNumber: 1,
    nextCommentId: 1,
  };
  store.nextRepoId += 1;
  store.seq += 1;
  store.repos.set(name, repo);
  return repo;
}

/** The Relay global id for a record: base64url of `kind:part:part...`, opaque and stable. */
function globalId(kind: string, ...parts: Array<string | number>): string {
  return b64urlEncode([kind, ...parts.map(String)].join(':'));
}

function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = b64urlDecode(id);
    const parts = text.split(':');
    const kind = parts.shift();
    if (kind === undefined || parts.length === 0) return null;
    return { kind, parts };
  } catch {
    return null;
  }
}

function repoByGlobalId(id: string): Repo | undefined {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'repo') return undefined;
  const dbId = Number(decoded.parts[0]);
  if (!Number.isInteger(dbId)) return undefined;
  for (const repo of store.repos.values()) if (repo.id === dbId) return repo;
  return undefined;
}

// -------------------------------------------------------------------------------------------
// The public JSON views of records (extra fields are fine: the suite checks named ones)
// -------------------------------------------------------------------------------------------

function userJson(): Record<string, unknown> {
  return { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User', site_admin: false };
}

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: globalId('repo', repo.id),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    has_issues: true,
    has_pull_requests: true,
  };
}

function labelJson(label: Label): Record<string, unknown> {
  return { name: label.name, color: label.color, description: label.description };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: globalId('issue', repo.id, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map(labelJson),
    user: userJson(),
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function commentJson(comment: IssueComment): Record<string, unknown> {
  return { id: comment.id, body: comment.body, user: userJson(), created_at: comment.createdAt };
}

function pullJson(repo: Repo, pull: PullRequest): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: globalId('pr', repo.id, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.head, sha: pull.headSha, label: `${repo.owner}:${pull.head}` },
    base: { ref: pull.base, sha: pull.baseSha, label: `${repo.owner}:${pull.base}` },
    user: userJson(),
    created_at: pull.createdAt,
  };
}

// -------------------------------------------------------------------------------------------
// Shared repository operations (REST, GraphQL and MCP all run through these)
// -------------------------------------------------------------------------------------------

/** Resolve a ref name, a full ref or a bare oid to the oid it points at, tags unpeeled. */
function resolveRef(repo: Repo, ref: string): string | null {
  if (isOid(ref)) return repo.objects.has(ref) ? ref : null;
  if (ref.startsWith('refs/')) return repo.refs.get(ref) ?? null;
  return repo.refs.get(`refs/heads/${ref}`) ?? repo.refs.get(`refs/tags/${ref}`) ?? null;
}

/** The commit a ref names, following annotated tags. */
function commitAtRef(repo: Repo, ref: string): string | null {
  const oid = resolveRef(repo, ref);
  if (oid === null) return null;
  const peeled = peelTo(repo.objects, oid);
  const object = repo.objects.get(peeled);
  return object !== undefined && object.type === 'commit' ? peeled : null;
}

/** The tree a ref names, or null when the ref has no commit yet. */
function treeAtRef(repo: Repo, ref: string): string | null {
  const commitOid = commitAtRef(repo, ref);
  if (commitOid === null) return null;
  const commit = repo.objects.get(commitOid);
  if (commit === undefined) return null;
  return parseCommit(commit.data).tree;
}

/** The flat file map at a ref, or null when the ref has no commit yet. */
function filesAtRef(repo: Repo, ref: string): FileMap | null {
  const treeOid = treeAtRef(repo, ref);
  if (treeOid === null) return null;
  const files: FileMap = new Map();
  flattenTree(repo.objects, treeOid, '', files);
  return files;
}

function createIssueRecord(repo: Repo, title: string, body: string, labels: Label[]): Issue {
  const issue: Issue = {
    id: store.nextIssueId,
    number: repo.nextNumber,
    title,
    body,
    state: 'open',
    labels: [...labels],
    createdSeq: store.seq,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    comments: [],
  };
  store.nextIssueId += 1;
  repo.nextNumber += 1;
  store.seq += 1;
  repo.issues.push(issue);
  return issue;
}

function createPullRecord(repo: Repo, title: string, body: string, head: string, base: string, headSha: string, baseSha: string): PullRequest {
  const pull: PullRequest = {
    id: store.nextPullId,
    number: repo.nextNumber,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    head,
    base,
    headSha,
    baseSha,
    createdSeq: store.seq,
    createdAt: nowIso(),
  };
  store.nextPullId += 1;
  repo.nextNumber += 1;
  store.seq += 1;
  repo.pulls.push(pull);
  return pull;
}

/**
 * Write one file at a ref and commit it. When the branch does not exist yet it is created:
 * from the default branch tip when the repository has one, or as the repository's first
 * branch when it has none. Answers the new commit oid and blob oid.
 */
function commitFile(
  repo: Repo,
  branch: string,
  path: string,
  content: Buffer,
  message: string,
): { commitSha: string; blobSha: string } {
  const blobSha = storeObject(repo.objects, 'blob', content);
  const currentFiles = filesAtRef(repo, branch) ?? new Map<string, { oid: string; mode: string }>();
  const tip = commitAtRef(repo, branch);
  currentFiles.set(path, { oid: blobSha, mode: '100644' });
  const treeSha = buildTreeFromMap(repo.objects, currentFiles);
  const timestamp = nowUnix();
  const commitSha = storeObject(
    repo.objects,
    'commit',
    buildCommit({
      tree: treeSha,
      parents: tip === null ? [] : [tip],
      author: identLine(timestamp),
      committer: identLine(timestamp),
      message,
    }),
  );
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  return { commitSha, blobSha };
}

/** Remove one file at a ref and commit the removal; answers the new commit oid. */
function deleteFile(repo: Repo, branch: string, path: string, message: string): string | null {
  const currentFiles = filesAtRef(repo, branch);
  const tip = commitAtRef(repo, branch);
  if (currentFiles === null || tip === null || !currentFiles.has(path)) return null;
  currentFiles.delete(path);
  const treeSha = buildTreeFromMap(repo.objects, currentFiles);
  const timestamp = nowUnix();
  const commitSha = storeObject(
    repo.objects,
    'commit',
    buildCommit({
      tree: treeSha,
      parents: [tip],
      author: identLine(timestamp),
      committer: identLine(timestamp),
      message,
    }),
  );
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  return commitSha;
}

/** The first common ancestor of two commits, by breadth-first search from the head side. */
function mergeBase(repo: Repo, ours: string, theirs: string): string | null {
  const oursAncestors = reachableCommits(repo.objects, [ours]);
  const queue: string[] = [theirs];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (oursAncestors.has(oid)) return oid;
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return null;
}

interface MergeOutcome {
  ok: true;
  commitSha: string;
  treeSha: string;
}
interface MergeConflict {
  ok: false;
  path: string;
}

/**
 * Three-way merge of `theirs` into the tip of `baseBranch`, with `base` as the merge base.
 * A path both sides changed differently is a conflict; anything else resolves.
 */
function threeWayMerge(repo: Repo, baseBranch: string, baseCommit: string, headCommit: string): MergeOutcome | MergeConflict {
  const baseFiles = filesAtRef(repo, baseCommit) ?? new Map<string, { oid: string; mode: string }>();
  const oursTip = commitAtRef(repo, baseBranch);
  if (oursTip === null) return { ok: false, path: '' };
  const oursFiles = filesAtRef(repo, oursTip) ?? new Map<string, { oid: string; mode: string }>();
  const theirsFiles = filesAtRef(repo, headCommit) ?? new Map<string, { oid: string; mode: string }>();
  const merged: FileMap = new Map(oursFiles);
  const paths = new Set([...baseFiles.keys(), ...oursFiles.keys(), ...theirsFiles.keys()]);
  for (const path of paths) {
    const base = baseFiles.get(path);
    const ours = oursFiles.get(path);
    const theirs = theirsFiles.get(path);
    if (theirs === undefined) {
      if (ours === undefined) {
        merged.delete(path); // Both sides deleted it.
      } else if (base === undefined) {
        // Only ours ever had it: keep ours.
      } else if (ours.oid === base.oid) {
        merged.delete(path); // Ours unchanged, theirs deleted it.
      } else {
        return { ok: false, path }; // Ours modified it, theirs deleted it.
      }
      continue;
    }
    if (ours === undefined) {
      if (base === undefined) {
        merged.set(path, theirs); // Only theirs ever had it: take it.
      } else if (theirs.oid === base.oid) {
        merged.delete(path); // Theirs unchanged, ours deleted it.
      } else {
        return { ok: false, path }; // Theirs modified it, ours deleted it.
      }
      continue;
    }
    if (theirs.oid === ours.oid) continue; // Both sides agree.
    if (base !== undefined && theirs.oid === base.oid) continue; // Theirs unchanged: keep ours.
    if (base !== undefined && ours.oid === base.oid) {
      merged.set(path, theirs); // Ours unchanged: take theirs.
      continue;
    }
    return { ok: false, path }; // Both sides changed it differently.
  }
  const treeSha = buildTreeFromMap(repo.objects, merged);
  return { ok: true, commitSha: '', treeSha };
}

/** Squash-merge (or merge) a pull request onto its base branch. */
function mergePullRequest(
  repo: Repo,
  pull: PullRequest,
  method: string,
): { ok: true; commitSha: string } | { ok: false; status: number; message: string } {
  const baseTip = commitAtRef(repo, pull.base);
  const headTip = commitAtRef(repo, pull.head);
  if (baseTip === null || headTip === null) return { ok: false, status: 409, message: 'The head or base branch has no commit' };
  const base = mergeBase(repo, baseTip, headTip) ?? baseTip;
  const merged = threeWayMerge(repo, pull.base, base, headTip);
  if (!merged.ok) return { ok: false, status: 405, message: 'Merge conflict' };
  const timestamp = nowUnix();
  const parents = method === 'merge' ? [baseTip, headTip] : [baseTip];
  const commitSha = storeObject(
    repo.objects,
    'commit',
    buildCommit({
      tree: merged.treeSha,
      parents,
      author: identLine(timestamp),
      committer: identLine(timestamp),
      message: `${pull.title} (#${pull.number})`,
    }),
  );
  repo.refs.set(`refs/heads/${pull.base}`, commitSha);
  pull.merged = true;
  pull.state = 'closed';
  pull.mergedAt = nowIso();
  pull.mergeCommitSha = commitSha;
  pull.baseSha = commitSha;
  return { ok: true, commitSha };
}

/** Whether a pull request can merge cleanly right now (its mergeable flag). */
function pullMergeable(repo: Repo, pull: PullRequest): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pull.merged) return 'MERGEABLE';
  const baseTip = commitAtRef(repo, pull.base);
  const headTip = commitAtRef(repo, pull.head);
  if (baseTip === null || headTip === null) return 'UNKNOWN';
  const base = mergeBase(repo, baseTip, headTip) ?? baseTip;
  const merged = threeWayMerge(repo, pull.base, base, headTip);
  return merged.ok ? 'MERGEABLE' : 'CONFLICTING';
}

/** The changed files between two commits, with line counts. */
function diffFiles(
  repo: Repo,
  baseCommit: string,
  headCommit: string,
): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const baseFiles = filesAtRef(repo, baseCommit) ?? new Map<string, { oid: string; mode: string }>();
  const headFiles = filesAtRef(repo, headCommit) ?? new Map<string, { oid: string; mode: string }>();
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> = [];
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of [...paths].sort()) {
    const base = baseFiles.get(path);
    const head = headFiles.get(path);
    if (base !== undefined && head !== undefined && base.oid === head.oid) continue;
    const oldText = base === undefined ? '' : (repo.objects.get(base.oid)?.data.toString('utf8') ?? '');
    const newText = head === undefined ? '' : (repo.objects.get(head.oid)?.data.toString('utf8') ?? '');
    const counts = lineDiffCounts(oldText, newText);
    const status = base === undefined ? 'added' : head === undefined ? 'removed' : 'modified';
    out.push({ filename: path, status, additions: counts.additions, deletions: counts.deletions, changes: counts.additions + counts.deletions });
  }
  return out;
}

// -------------------------------------------------------------------------------------------
// HTTP plumbing: bodies, JSON answers, auth
// -------------------------------------------------------------------------------------------

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 64 * 1024 * 1024) {
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId(),
    ...extraHeaders,
  });
  res.end(text);
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string, extraHeaders: Record<string, string> = {}): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': requestId(),
    ...extraHeaders,
  });
  res.end(body);
}

function sendNoContent(res: ServerResponse, status: number): void {
  res.writeHead(status, { 'content-length': 0, 'x-github-request-id': requestId() });
  res.end();
}

function jsonError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

/**
 * The request carries the shop token: a Bearer token, or Basic auth with the token as
 * the password (how a plain git client authenticates). With no token configured, any
 * non-empty credential is accepted.
 */
function authed(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  const bearer = /^Bearer (.+)$/.exec(header);
  if (bearer !== null) {
    if (SHOP_TOKEN === '') return bearer[1] !== '';
    return bearer[1] === SHOP_TOKEN;
  }
  const basic = /^Basic (.+)$/.exec(header);
  if (basic !== null) {
    try {
      const decoded = Buffer.from(basic[1] as string, 'base64').toString('utf8');
      const colon = decoded.indexOf(':');
      const password = colon < 0 ? decoded : decoded.slice(colon + 1);
      if (SHOP_TOKEN === '') return password !== '';
      return password === SHOP_TOKEN;
    } catch {
      return false;
    }
  }
  return false;
}

interface RouteParams {
  segments: string[];
  query: URLSearchParams;
  host: string;
}

function parseRoute(req: IncomingMessage): RouteParams {
  let url: URL;
  try {
    url = new URL(req.url ?? '/', 'http://entry');
  } catch {
    url = new URL('/', 'http://entry');
  }
  const segments = url.pathname
    .split('/')
    .filter((part) => part !== '')
    .map((part) => {
      try {
        return decodeURIComponent(part);
      } catch {
        return part;
      }
    });
  return { segments, query: url.searchParams, host: req.headers.host ?? '127.0.0.1' };
}

/** Parse a JSON body; answers 400 itself and returns null when the body is malformed. */
async function readJsonBody(req: IncomingMessage, res: ServerResponse): Promise<Record<string, unknown> | null> {
  const raw = await readBody(req);
  if (raw.length === 0) return {};
  try {
    const parsed: unknown = JSON.parse(raw.toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    return {};
  } catch {
    jsonError(res, 400, 'Invalid JSON body');
    return null;
  }
}

function pageParams(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const perPage = Math.min(100, Math.max(1, Number(query.get('per_page') ?? '30') || 30));
  return { page, perPage };
}

/** Slice a list into one page and build the Link header for the next page, if any. */
function paginate<T>(items: readonly T[], page: number, perPage: number, baseUrl: string): { pageItems: T[]; link: string | null } {
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  const pageItems = items.slice(start, start + perPage);
  let link: string | null = null;
  if (page < totalPages) {
    const next = `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}page=${page + 1}&per_page=${perPage}`;
    const last = `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}page=${totalPages}&per_page=${perPage}`;
    link = `<${next}>; rel="next", <${last}>; rel="last"`;
  }
  return { pageItems, link };
}

function linkHeader(res: ServerResponse, link: string | null): Record<string, string> {
  return link === null ? {} : { link };
}

/** The immediate children of a directory at a ref, with real blob/tree shas; null when absent. */
function directoryEntries(repo: Repo, ref: string, dirPath: string): Array<Record<string, unknown>> | null {
  const treeOid = treeAtRef(repo, ref);
  if (treeOid === null) return null;
  let current = treeOid;
  if (dirPath !== '') {
    for (const segment of dirPath.split('/')) {
      const tree = repo.objects.get(current);
      if (tree === undefined) return null;
      const entry = parseTree(tree.data).find((item) => item.name === segment && item.mode === '40000');
      if (entry === undefined) return null;
      current = entry.oid;
    }
  }
  const tree = repo.objects.get(current);
  if (tree === undefined || tree.type !== 'tree') return null;
  const entries: Array<Record<string, unknown>> = [];
  for (const entry of parseTree(tree.data)) {
    const path = dirPath === '' ? entry.name : `${dirPath}/${entry.name}`;
    if (entry.mode === '40000') {
      entries.push({ type: 'dir', name: entry.name, path, sha: entry.oid, size: 0 });
    } else {
      const blob = repo.objects.get(entry.oid);
      entries.push({ type: 'file', name: entry.name, path, sha: entry.oid, size: blob?.data.length ?? 0 });
    }
  }
  entries.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return entries;
}

// -------------------------------------------------------------------------------------------
// REST v3
// -------------------------------------------------------------------------------------------

async function handleRest(req: IncomingMessage, res: ServerResponse, route: RouteParams): Promise<boolean> {
  const method = req.method ?? 'GET';
  const seg = route.segments;
  if (seg[0] !== 'api' || seg[1] !== 'v3') return false;
  const rest = seg.slice(2);
  const path = `/${seg.join('/')}`;

  // GET /api/v3/ — the API root.
  if (rest.length === 0) {
    if (method !== 'GET') {
      jsonError(res, 404, 'Not Found');
      return true;
    }
    sendJson(
      res,
      200,
      {
        current_user_url: '/api/v3/user',
        current_user_authorizations_html_url: '/api/v3/authorizations',
        authorizations_url: '/api/v3/authorizations',
        rate_limit_url: '/api/v3/rate_limit',
        user_url: '/api/v3/users/{user}',
        repository_url: '/api/v3/repos/{owner}/{repo}',
      },
      { 'x-oauth-scopes': 'repo, read:org' },
    );
    return true;
  }

  if (rest[0] === 'meta' && rest.length === 1) {
    if (method !== 'GET') {
      jsonError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, { installed_version: SERVER_VERSION });
    return true;
  }

  if (rest[0] === 'user' && rest.length === 1) {
    if (method !== 'GET') {
      jsonError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, { ...userJson(), name: VIEWER_LOGIN, email: VIEWER_EMAIL });
    return true;
  }

  // POST /api/v3/user/repos and GET /api/v3/user/repos
  if (rest[0] === 'user' && rest[1] === 'repos' && rest.length === 2) {
    if (method === 'POST') {
      const body = await readJsonBody(req, res);
      if (body === null) return true;
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (name === '' || name.includes('/')) {
        jsonError(res, 422, 'Repository name is required');
        return true;
      }
      if (store.repos.has(name)) {
        jsonError(res, 422, `Repository ${name} already exists`);
        return true;
      }
      const repo = createRepoRecord(name, body.private === true, typeof body.description === 'string' ? body.description : '');
      sendJson(res, 201, repoJson(repo));
      return true;
    }
    if (method === 'GET') {
      const { page, perPage } = pageParams(route.query);
      const repos = [...store.repos.values()].sort((a, b) => a.createdSeq - b.createdSeq);
      const base = `http://${route.host}/api/v3/user/repos?per_page=${perPage}`;
      const { pageItems, link } = paginate(repos, page, perPage, base);
      sendJson(res, 200, pageItems.map(repoJson), linkHeader(res, link));
      return true;
    }
    jsonError(res, 404, 'Not Found');
    return true;
  }

  // /api/v3/repos/{owner}/{name}/...
  if (rest[0] === 'repos' && rest.length >= 3) {
    const owner = rest[1] as string;
    const name = rest[2] as string;
    const repo = findRepo(owner, name);
    const tail = rest.slice(3);

    if (tail.length === 0) {
      if (method === 'GET') {
        if (repo === undefined) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'PATCH') {
        if (repo === undefined) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        const body = await readJsonBody(req, res);
        if (body === null) return true;
        if (typeof body.description === 'string') repo.description = body.description;
        if (body.private === true || body.private === false) repo.isPrivate = body.private;
        repo.updatedAt = nowIso();
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        if (repo === undefined) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        store.repos.delete(name);
        sendNoContent(res, 204);
        return true;
      }
      jsonError(res, 404, 'Not Found');
      return true;
    }

    if (repo === undefined) {
      jsonError(res, 404, 'Not Found');
      return true;
    }

    // POST /repos/{o}/{r}/git/refs and GET /repos/{o}/{r}/git/refs/heads/{branch}
    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'POST' && tail.length === 2) {
        const body = await readJsonBody(req, res);
        if (body === null) return true;
        const ref = typeof body.ref === 'string' ? body.ref : '';
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (!ref.startsWith('refs/heads/') && !ref.startsWith('refs/tags/')) {
          jsonError(res, 422, 'Invalid ref');
          return true;
        }
        if (!isOid(sha) || !repo.objects.has(sha)) {
          jsonError(res, 422, 'Invalid sha');
          return true;
        }
        if (repo.refs.has(ref)) {
          jsonError(res, 422, `Ref ${ref} already exists`);
          return true;
        }
        repo.refs.set(ref, sha);
        sendJson(res, 201, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } });
        return true;
      }
      if (method === 'GET' && tail.length >= 4 && (tail[2] === 'heads' || tail[2] === 'tags')) {
        const refName = tail.slice(3).join('/');
        const ref = `refs/${tail[2]}/${refName}`;
        const sha = repo.refs.get(ref);
        if (sha === undefined) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } });
        return true;
      }
      jsonError(res, 404, 'Not Found');
      return true;
    }

    // GET /repos/{o}/{r}/branches and /branches/{branch}
    if (tail[0] === 'branches') {
      if (method === 'GET' && tail.length === 1) {
        const branches = [...repo.refs.entries()]
          .filter(([ref]) => ref.startsWith('refs/heads/'))
          .map(([ref, sha]) => ({ name: ref.slice('refs/heads/'.length), commit: { sha } }))
          .sort((a, b) => (a.name < b.name ? -1 : 1));
        sendJson(res, 200, branches);
        return true;
      }
      if (method === 'GET' && tail.length === 2) {
        const sha = repo.refs.get(`refs/heads/${tail[1]}`);
        if (sha === undefined) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, { name: tail[1], commit: { sha } });
        return true;
      }
      jsonError(res, 404, 'Not Found');
      return true;
    }

    // GET /repos/{o}/{r}/commits[?sha=<ref>]
    if (tail[0] === 'commits' && tail.length === 1) {
      if (method !== 'GET') {
        jsonError(res, 404, 'Not Found');
        return true;
      }
      const ref = route.query.get('sha') ?? repo.defaultBranch;
      const tip = commitAtRef(repo, ref);
      if (tip === null) {
        sendJson(res, 200, []);
        return true;
      }
      const commits: Array<Record<string, unknown>> = [];
      const seen = new Set<string>();
      // Index pointer instead of shift(): the walk is O(n), not O(n^2), on long histories.
      const stack: string[] = [tip];
      for (let at = 0; at < stack.length; at += 1) {
        const oid = stack[at] as string;
        if (seen.has(oid)) continue;
        const object = repo.objects.get(oid);
        if (object === undefined || object.type !== 'commit') continue;
        seen.add(oid);
        const view = parseCommit(object.data);
        // GitHub renders the message without the trailing newline the object
        // stores; the check compares against the message as submitted.
        const message = view.message.endsWith('\n') ? view.message.slice(0, -1) : view.message;
        commits.push({
          sha: oid,
          commit: { message, author: { name: VIEWER_LOGIN, email: VIEWER_EMAIL }, committer: { name: VIEWER_LOGIN, email: VIEWER_EMAIL } },
          parents: view.parents.map((parent) => ({ sha: parent })),
        });
        stack.push(...view.parents);
      }
      sendJson(res, 200, commits);
      return true;
    }

    // Contents: PUT / GET / DELETE /repos/{o}/{r}/contents/{path...}
    if (tail[0] === 'contents') {
      const contentPath = tail.slice(1).join('/');
      if (method === 'PUT') {
        const body = await readJsonBody(req, res);
        if (body === null) return true;
        const message = typeof body.message === 'string' ? body.message : 'Update';
        const branch = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
        const content = typeof body.content === 'string' ? body.content : '';
        let bytes: Buffer;
        try {
          bytes = b64decode(content);
        } catch {
          jsonError(res, 422, 'Invalid base64 content');
          return true;
        }
        const existingFiles = filesAtRef(repo, branch);
        const existing = existingFiles?.get(contentPath);
        const givenSha = typeof body.sha === 'string' ? body.sha : undefined;
        if (existing !== undefined) {
          if (givenSha === undefined) {
            jsonError(res, 422, 'sha is required to update a file');
            return true;
          }
          if (givenSha.toLowerCase() !== existing.oid.toLowerCase()) {
            jsonError(res, 409, 'The file has changed since the given sha');
            return true;
          }
        }
        const { commitSha, blobSha } = commitFile(repo, branch, contentPath, bytes, message);
        sendJson(res, existing === undefined ? 201 : 200, {
          content: { name: contentPath.split('/').pop() ?? '', path: contentPath, sha: blobSha, size: bytes.length, encoding: 'base64', type: 'file' },
          commit: { sha: commitSha },
        });
        return true;
      }
      if (method === 'GET') {
        const ref = route.query.get('ref') ?? repo.defaultBranch;
        const files = filesAtRef(repo, ref);
        if (files === null) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        if (contentPath === '') {
          const entries = directoryEntries(repo, ref, '');
          if (entries === null) {
            jsonError(res, 404, 'Not Found');
            return true;
          }
          sendJson(res, 200, entries);
          return true;
        }
        const file = files.get(contentPath);
        if (file !== undefined) {
          const blob = repo.objects.get(file.oid);
          sendJson(res, 200, {
            type: 'file',
            encoding: 'base64',
            content: b64encode(blob?.data ?? Buffer.alloc(0)),
            sha: file.oid,
            size: blob?.data.length ?? 0,
            name: contentPath.split('/').pop() ?? '',
            path: contentPath,
          });
          return true;
        }
        // A directory: the immediate children of contentPath.
        const entries = directoryEntries(repo, ref, contentPath);
        if (entries === null || entries.length === 0) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, entries);
        return true;
      }
      if (method === 'DELETE') {
        const body = await readJsonBody(req, res);
        if (body === null) return true;
        const message = typeof body.message === 'string' ? body.message : 'Delete';
        const branch = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
        const commitSha = deleteFile(repo, branch, contentPath, message);
        if (commitSha === null) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, { commit: { sha: commitSha } });
        return true;
      }
      jsonError(res, 404, 'Not Found');
      return true;
    }

    // Labels
    if (tail[0] === 'labels') {
      if (method === 'POST' && tail.length === 1) {
        const body = await readJsonBody(req, res);
        if (body === null) return true;
        const name = typeof body.name === 'string' ? body.name.trim() : '';
        if (name === '') {
          jsonError(res, 422, 'Label name is required');
          return true;
        }
        if (repo.labels.some((label) => label.name === name)) {
          jsonError(res, 422, `Label ${name} already exists`);
          return true;
        }
        const label: Label = {
          name,
          color: typeof body.color === 'string' ? body.color : 'ededed',
          description: typeof body.description === 'string' ? body.description : '',
        };
        repo.labels.push(label);
        sendJson(res, 201, labelJson(label));
        return true;
      }
      if (method === 'GET' && tail.length === 1) {
        sendJson(res, 200, repo.labels.map(labelJson));
        return true;
      }
      jsonError(res, 404, 'Not Found');
      return true;
    }

    // Issues
    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'POST') {
          const body = await readJsonBody(req, res);
          if (body === null) return true;
          const title = typeof body.title === 'string' ? body.title : '';
          const issueBody = typeof body.body === 'string' ? body.body : '';
          if (title === '') {
            jsonError(res, 422, 'Title is required');
            return true;
          }
          const wanted = Array.isArray(body.labels) ? (body.labels as unknown[]).filter((entry): entry is string => typeof entry === 'string') : [];
          const labels: Label[] = [];
          for (const name of wanted) {
            const label = repo.labels.find((entry) => entry.name === name);
            if (label === undefined) {
              jsonError(res, 422, `Label ${name} does not exist`);
              return true;
            }
            labels.push(label);
          }
          const issue = createIssueRecord(repo, title, issueBody, labels);
          sendJson(res, 201, issueJson(repo, issue));
          return true;
        }
        if (method === 'GET') {
          const state = route.query.get('state') ?? 'open';
          const sort = route.query.get('sort') ?? 'created';
          const direction = route.query.get('direction') ?? 'desc';
          let issues = [...repo.issues];
          if (state !== 'all') issues = issues.filter((issue) => issue.state === state);
          issues.sort((a, b) => {
            const order = sort === 'created' ? a.createdSeq - b.createdSeq : a.number - b.number;
            return direction === 'asc' ? order : -order;
          });
          const { page, perPage } = pageParams(route.query);
          const base = `http://${route.host}${path}?state=${state}&sort=${sort}&direction=${direction}&per_page=${perPage}`;
          const { pageItems, link } = paginate(issues, page, perPage, base);
          sendJson(res, 200, pageItems.map((issue) => issueJson(repo, issue)), linkHeader(res, link));
          return true;
        }
        jsonError(res, 404, 'Not Found');
        return true;
      }
      const number = Number(tail[1]);
      if (!Number.isInteger(number)) {
        jsonError(res, 404, 'Not Found');
        return true;
      }
      const issue = repo.issues.find((entry) => entry.number === number);
      if (tail.length === 2) {
        if (method === 'GET') {
          if (issue === undefined) {
            jsonError(res, 404, 'Not Found');
            return true;
          }
          sendJson(res, 200, issueJson(repo, issue));
          return true;
        }
        if (method === 'PATCH') {
          if (issue === undefined) {
            jsonError(res, 404, 'Not Found');
            return true;
          }
          const body = await readJsonBody(req, res);
          if (body === null) return true;
          if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
          if (typeof body.title === 'string') issue.title = body.title;
          if (typeof body.body === 'string') issue.body = body.body;
          issue.updatedAt = nowIso();
          sendJson(res, 200, issueJson(repo, issue));
          return true;
        }
        jsonError(res, 404, 'Not Found');
        return true;
      }
      if (tail[2] === 'comments') {
        if (issue === undefined) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        if (method === 'POST') {
          const body = await readJsonBody(req, res);
          if (body === null) return true;
          const text = typeof body.body === 'string' ? body.body : '';
          const comment: IssueComment = { id: repo.nextCommentId, body: text, createdAt: nowIso() };
          repo.nextCommentId += 1;
          issue.comments.push(comment);
          sendJson(res, 201, commentJson(comment));
          return true;
        }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map(commentJson));
          return true;
        }
        jsonError(res, 404, 'Not Found');
        return true;
      }
      jsonError(res, 404, 'Not Found');
      return true;
    }

    // Pull requests
    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'POST') {
          const body = await readJsonBody(req, res);
          if (body === null) return true;
          const title = typeof body.title === 'string' ? body.title : '';
          const prBody = typeof body.body === 'string' ? body.body : '';
          const head = typeof body.head === 'string' ? body.head : '';
          const base = typeof body.base === 'string' ? body.base : '';
          if (title === '' || head === '' || base === '') {
            jsonError(res, 422, 'title, head and base are required');
            return true;
          }
          const headSha = commitAtRef(repo, head);
          const baseSha = commitAtRef(repo, base);
          if (headSha === null || baseSha === null) {
            jsonError(res, 422, 'head or base branch does not exist');
            return true;
          }
          if (repo.pulls.some((pull) => pull.head === head && pull.base === base && pull.state === 'open')) {
            jsonError(res, 422, 'A pull request is already open for this head and base');
            return true;
          }
          const pull = createPullRecord(repo, title, prBody, head, base, headSha, baseSha);
          sendJson(res, 201, pullJson(repo, pull));
          return true;
        }
        if (method === 'GET') {
          const state = route.query.get('state') ?? 'open';
          let pulls = [...repo.pulls];
          if (state !== 'all') pulls = pulls.filter((pull) => pull.state === state);
          pulls.sort((a, b) => b.createdSeq - a.createdSeq);
          const { page, perPage } = pageParams(route.query);
          const base = `http://${route.host}${path}?state=${state}&per_page=${perPage}`;
          const { pageItems, link } = paginate(pulls, page, perPage, base);
          sendJson(res, 200, pageItems.map((pull) => pullJson(repo, pull)), linkHeader(res, link));
          return true;
        }
        jsonError(res, 404, 'Not Found');
        return true;
      }
      const number = Number(tail[1]);
      if (!Number.isInteger(number)) {
        jsonError(res, 404, 'Not Found');
        return true;
      }
      const pull = repo.pulls.find((entry) => entry.number === number);
      if (tail.length === 2) {
        if (method === 'GET') {
          if (pull === undefined) {
            jsonError(res, 404, 'Not Found');
            return true;
          }
          sendJson(res, 200, pullJson(repo, pull));
          return true;
        }
        jsonError(res, 404, 'Not Found');
        return true;
      }
      if (tail[2] === 'files' && tail.length === 3) {
        if (method !== 'GET') {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        if (pull === undefined) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        const baseTip = commitAtRef(repo, pull.base) ?? pull.baseSha;
        const headTip = commitAtRef(repo, pull.head) ?? pull.headSha;
        sendJson(res, 200, diffFiles(repo, baseTip, headTip));
        return true;
      }
      if (tail[2] === 'merge' && tail.length === 3) {
        if (method !== 'PUT') {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        if (pull === undefined) {
          jsonError(res, 404, 'Not Found');
          return true;
        }
        if (pull.merged || pull.state !== 'open') {
          jsonError(res, 405, 'Pull request is already merged or closed');
          return true;
        }
        const body = await readJsonBody(req, res);
        if (body === null) return true;
        const mergeMethod = typeof body.merge_method === 'string' ? body.merge_method : 'squash';
        const merged = mergePullRequest(repo, pull, mergeMethod);
        if (!merged.ok) {
          jsonError(res, merged.status, merged.message);
          return true;
        }
        sendJson(res, 200, { merged: true, sha: merged.commitSha, message: `Merged pull request #${pull.number}` });
        return true;
      }
      jsonError(res, 404, 'Not Found');
      return true;
    }

    jsonError(res, 404, 'Not Found');
    return true;
  }

  return false;
}

// -------------------------------------------------------------------------------------------
// Git smart HTTP
// -------------------------------------------------------------------------------------------

const UPLOAD_V2_CAPS = ['agent', 'ls-refs=unborn', 'fetch=shallow', 'object-format=sha1'];
const UPLOAD_V0_CAPS =
  'symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta multi_ack multi_ack_detailed shallow agent=makefun-github-core-clone/1';
const RECEIVE_V0_CAPS = 'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=makefun-github-core-clone/1';

function sortedRefNames(repo: Repo): string[] {
  return [...repo.refs.keys()].sort();
}

/** The v0 ref advertisement lines for a repo (first line carries the capabilities). */
function v0RefLines(repo: Repo, caps: string): Buffer[] {
  const lines: Buffer[] = [];
  const headOid = repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? ZERO_OID;
  const names = sortedRefNames(repo);
  if (names.length === 0) {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
    return lines;
  }
  lines.push(pktLine(`${headOid} HEAD\0${caps}\n`));
  for (const name of names) {
    lines.push(pktLine(`${repo.refs.get(name) as string} ${name}\n`));
  }
  for (const name of names) {
    const oid = repo.refs.get(name) as string;
    const object = repo.objects.get(oid);
    if (object !== undefined && object.type === 'tag') {
      const peeled = peelTo(repo.objects, oid);
      lines.push(pktLine(`${peeled} ${name}^{}\n`));
    }
  }
  return lines;
}

function gitAdvertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack', protocol2: boolean): Buffer {
  const chunks: Buffer[] = [];
  chunks.push(pktLine(`# service=${service}\n`), PKT_FLUSH);
  if (protocol2) {
    chunks.push(pktLine('version 2\n'));
    for (const cap of UPLOAD_V2_CAPS) chunks.push(pktLine(`${cap}\n`));
    chunks.push(PKT_FLUSH);
    return Buffer.concat(chunks);
  }
  const caps = service === 'git-upload-pack' ? UPLOAD_V0_CAPS : RECEIVE_V0_CAPS;
  chunks.push(...v0RefLines(repo, caps), PKT_FLUSH);
  return Buffer.concat(chunks);
}

interface FetchPlan {
  toSend: Map<string, GitObject>;
  shallow: string[];
  unshallow: string[];
  acks: string[];
}

/** Work out what a fetch sends: new objects, shallow boundaries and acknowledgments. */
function planFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  oldShallow: string[],
  depth: number | null,
): FetchPlan {
  const heldCommits = new Set<string>();
  const shallowSet = new Set(oldShallow);
  // Commits the client already holds: reachable from its haves, not crossing its boundaries.
  const walkHeld = (start: string): void => {
    const stack: string[] = [peelTo(repo.objects, start)];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (heldCommits.has(oid)) continue;
      const object = repo.objects.get(oid);
      if (object === undefined || object.type !== 'commit') continue;
      heldCommits.add(oid);
      if (shallowSet.has(oid)) continue;
      for (const parent of parseCommit(object.data).parents) stack.push(parent);
    }
  };
  for (const have of haves) if (repo.objects.has(have)) walkHeld(have);
  // Objects the client already holds: the have commits themselves and the trees
  // and blobs under them. Never the ancestors of a held commit: a shallow clone
  // holds only its boundary commits, and a deepen has to deliver the parent
  // that the boundary hides. (reachableObjects walks parents too, which made
  // the final toSend filter swallow exactly the parent a deepen must send.)
  const heldObjects = new Set<string>();
  const collectTreeObjects = (oid: string): void => {
    const stack: string[] = [oid];
    while (stack.length > 0) {
      const current = stack.pop() as string;
      if (heldObjects.has(current)) continue;
      const object = repo.objects.get(current);
      if (object === undefined) continue;
      heldObjects.add(current);
      if (object.type === 'tree') {
        for (const entry of parseTree(object.data)) stack.push(entry.oid);
      } else if (object.type === 'tag') {
        stack.push(parseTag(object.data).object);
      }
    }
  };
  for (const oid of haves) if (repo.objects.has(oid)) heldObjects.add(oid);
  for (const commit of heldCommits) {
    heldObjects.add(commit);
    const object = repo.objects.get(commit);
    if (object !== undefined && object.type === 'commit') {
      collectTreeObjects(parseCommit(object.data).tree);
    }
  }

  const acks = haves.filter((have) => repo.objects.has(have));
  const toSend = new Map<string, GitObject>();
  const shallow: string[] = [];
  const unshallow: string[] = [];

  // The wanted tips, peeled to commits, keeping wanted tag objects themselves in the pack.
  const wantCommits: string[] = [];
  for (const want of wants) {
    const object = repo.objects.get(want);
    if (object === undefined) continue;
    if (object.type === 'tag') {
      if (!heldObjects.has(want)) toSend.set(want, object);
      wantCommits.push(peelTo(repo.objects, want));
    } else if (object.type === 'commit') {
      wantCommits.push(want);
    }
  }

  if (depth !== null) {
    // Breadth-first levels from the wants; level < depth is sent, level depth-1 is shallow.
    const level = new Map<string, number>();
    const queue: string[] = [];
    for (const commit of wantCommits) {
      if (!level.has(commit)) {
        level.set(commit, 0);
        queue.push(commit);
      }
    }
    const sentCommits = new Set<string>();
    // Index pointer instead of shift(): the walk is O(n), not O(n^2), on long histories.
    for (let head = 0; head < queue.length; head += 1) {
      const oid = queue[head] as string;
      const at = level.get(oid) as number;
      if (at < depth) sentCommits.add(oid);
      if (at >= depth) continue;
      const object = repo.objects.get(oid);
      if (object === undefined || object.type !== 'commit') continue;
      for (const parent of parseCommit(object.data).parents) {
        if (!level.has(parent)) {
          level.set(parent, at + 1);
          queue.push(parent);
        }
      }
    }
    for (const oid of sentCommits) {
      if (heldCommits.has(oid)) continue;
      const object = repo.objects.get(oid);
      if (object === undefined) continue;
      toSend.set(oid, object);
      const tree = parseCommit(object.data).tree;
      for (const reachable of reachableObjects(repo.objects, [tree])) {
        const entry = repo.objects.get(reachable);
        if (entry !== undefined && !heldObjects.has(reachable)) toSend.set(reachable, entry);
      }
      if ((level.get(oid) as number) === depth - 1) shallow.push(oid);
    }
    for (const boundary of oldShallow) {
      const object = repo.objects.get(boundary);
      if (object === undefined || object.type !== 'commit') continue;
      const parents = parseCommit(object.data).parents;
      if (parents.every((parent) => heldCommits.has(parent) || sentCommits.has(parent))) unshallow.push(boundary);
    }
  } else {
    const wanted = reachableCommits(repo.objects, wantCommits);
    for (const oid of wanted) {
      if (heldCommits.has(oid)) continue;
      const object = repo.objects.get(oid);
      if (object === undefined) continue;
      toSend.set(oid, object);
    }
    for (const oid of [...toSend.keys()]) {
      const object = repo.objects.get(oid);
      if (object === undefined || object.type !== 'commit') continue;
      const tree = parseCommit(object.data).tree;
      for (const reachable of reachableObjects(repo.objects, [tree])) {
        const entry = repo.objects.get(reachable);
        if (entry !== undefined && !heldObjects.has(reachable)) toSend.set(reachable, entry);
      }
    }
  }
  for (const oid of [...toSend.keys()]) if (heldObjects.has(oid)) toSend.delete(oid);
  return { toSend, shallow, unshallow, acks };
}

/** The v2 ls-refs answer lines for a repo, filtered by the requested prefixes. */
function lsRefsLines(repo: Repo, prefixes: string[], peel: boolean, symrefs: boolean, unborn: boolean): Buffer[] {
  const lines: Buffer[] = [];
  const names = sortedRefNames(repo);
  const headOid = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  if (names.length === 0) {
    if (unborn && keep('HEAD')) {
      lines.push(pktLine(`unborn HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`));
    }
    lines.push(PKT_FLUSH);
    return lines;
  }
  if (headOid !== undefined && keep('HEAD')) {
    lines.push(pktLine(`${headOid} HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`));
  }
  for (const name of names) {
    if (!keep(name)) continue;
    const oid = repo.refs.get(name) as string;
    let suffix = '';
    if (peel) {
      const object = repo.objects.get(oid);
      if (object !== undefined && object.type === 'tag') suffix = ` peeled:${peelTo(repo.objects, oid)}`;
    }
    lines.push(pktLine(`${oid} ${name}${suffix}\n`));
  }
  lines.push(PKT_FLUSH);
  return lines;
}

/** Read receive-pack command lines up to the flush; answers the commands and the pack offset. */
function readPushCommands(buf: Buffer): { commands: Array<{ oldOid: string; newOid: string; ref: string }>; packOffset: number } {
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let offset = 0;
  for (;;) {
    if (offset + 4 > buf.length) throw new Error('push body truncated');
    const head = buf.subarray(offset, offset + 4).toString('ascii');
    if (head === '0000') {
      offset += 4;
      break;
    }
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`bad pkt-line length ${JSON.stringify(head)}`);
    const length = parseInt(head, 16);
    if (length < 4 || offset + length > buf.length) throw new Error('pkt-line length out of range');
    const line = buf.subarray(offset + 4, offset + length).toString('utf8').replace(/\n$/, '');
    offset += length;
    const nul = line.indexOf('\0');
    const commandText = nul < 0 ? line : line.slice(0, nul);
    const parts = commandText.split(' ');
    if (parts.length !== 3 || !isOid(parts[0]) || !isOid(parts[1])) throw new Error(`bad push command ${JSON.stringify(commandText)}`);
    commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts[2] as string });
  }
  return { commands, packOffset: offset };
}

function evalPushCommand(repo: Repo, command: { oldOid: string; newOid: string; ref: string }): { ok: boolean; reason: string } {
  const current = repo.refs.get(command.ref);
  if (command.newOid === ZERO_OID) {
    if (current === undefined) return { ok: false, reason: 'cannot delete a ref that does not exist' };
    if (command.oldOid !== ZERO_OID && command.oldOid !== current) return { ok: false, reason: 'non-fast-forward' };
    repo.refs.delete(command.ref);
    return { ok: true, reason: '' };
  }
  if (!repo.objects.has(command.newOid)) return { ok: false, reason: 'object not found' };
  if (command.oldOid === ZERO_OID) {
    if (current !== undefined) return { ok: false, reason: 'already exists' };
    repo.refs.set(command.ref, command.newOid);
    return { ok: true, reason: '' };
  }
  if (current === undefined || current !== command.oldOid) return { ok: false, reason: 'non-fast-forward' };
  const newCommit = peelTo(repo.objects, command.newOid);
  const newObject = repo.objects.get(newCommit);
  if (newObject === undefined || newObject.type !== 'commit') return { ok: false, reason: 'non-fast-forward' };
  if (!isAncestor(repo.objects, command.oldOid, newCommit)) return { ok: false, reason: 'non-fast-forward' };
  repo.refs.set(command.ref, command.newOid);
  return { ok: true, reason: '' };
}

async function handleGit(req: IncomingMessage, res: ServerResponse, route: RouteParams): Promise<boolean> {
  const method = req.method ?? 'GET';
  const seg = route.segments;
  if (seg.length < 2 || !seg[1].endsWith('.git')) return false;
  const owner = seg[0] as string;
  const name = seg[1].slice(0, -4);
  const service = seg[2] ?? '';
  const repo = findRepo(owner, name);

  if (method === 'GET' && service === 'info' && seg[3] === 'refs') {
    const wanted = route.query.get('service') ?? '';
    if (repo === undefined) {
      jsonError(res, 404, 'Not Found');
      return true;
    }
    if (wanted !== 'git-upload-pack' && wanted !== 'git-receive-pack') {
      jsonError(res, 404, 'Not Found');
      return true;
    }
    const protocol2 = wanted === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
    const body = gitAdvertisement(repo, wanted, protocol2);
    sendRaw(res, 200, body, `application/x-${wanted}-advertisement`);
    return true;
  }

  if (method === 'POST' && service === 'git-upload-pack') {
    if (repo === undefined) {
      jsonError(res, 404, 'Not Found');
      return true;
    }
    const body = await readBody(req);
    let lines: string[];
    try {
      lines = pktTextLines(body);
    } catch {
      sendRaw(res, 400, Buffer.from('bad pkt-line\n', 'utf8'), 'text/plain');
      return true;
    }
    const protocol2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    const command = lines[0] ?? '';
    if (protocol2 && command === 'command=ls-refs') {
      const prefixes: string[] = [];
      let peel = false;
      let symrefs = false;
      let unborn = false;
      for (const line of lines.slice(1)) {
        if (line === 'peel') peel = true;
        else if (line === 'symrefs') symrefs = true;
        else if (line === 'unborn') unborn = true;
        else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
      }
      const out = Buffer.concat(lsRefsLines(repo, prefixes, peel, symrefs, unborn));
      sendRaw(res, 200, out, 'application/x-git-upload-pack-result');
      return true;
    }
    if (protocol2 && command === 'command=fetch') {
      const wants: string[] = [];
      const haves: string[] = [];
      const shallow: string[] = [];
      let depth: number | null = null;
      for (const line of lines.slice(1)) {
        if (line.startsWith('want ')) wants.push(line.slice(5));
        else if (line.startsWith('have ')) haves.push(line.slice(5));
        else if (line.startsWith('shallow ')) shallow.push(line.slice(8));
        else if (line.startsWith('deepen ')) depth = Number(line.slice(7));
      }
      const plan = planFetch(repo, wants, haves, shallow, depth);
      const chunks: Buffer[] = [];
      // The acknowledgments section only exists when the client negotiated with
      // have lines; a fresh fetch goes straight to shallow-info / packfile.
      if (haves.length > 0) {
        chunks.push(pktLine('acknowledgments\n'));
        if (plan.acks.length === 0) {
          chunks.push(pktLine('NAK\n'));
        } else {
          for (const ack of plan.acks) chunks.push(pktLine(`ACK ${ack}\n`));
          chunks.push(pktLine('ready\n'));
        }
        chunks.push(PKT_DELIM);
      }
      if (depth !== null && (plan.shallow.length > 0 || plan.unshallow.length > 0)) {
        chunks.push(pktLine('shallow-info\n'));
        for (const oid of plan.shallow) chunks.push(pktLine(`shallow ${oid}\n`));
        for (const oid of plan.unshallow) chunks.push(pktLine(`unshallow ${oid}\n`));
        chunks.push(PKT_DELIM);
      }
      if (plan.toSend.size > 0) {
        chunks.push(pktLine('packfile\n'));
        const pack = writePack([...plan.toSend.values()]);
        chunks.push(...sidebandPackets(pack));
      }
      chunks.push(PKT_FLUSH);
      sendRaw(res, 200, Buffer.concat(chunks), 'application/x-git-upload-pack-result');
      return true;
    }
    if (!protocol2) {
      // v0 fetch: wants, then a flush, then haves and done.
      const wants: string[] = [];
      const haves: string[] = [];
      const shallow: string[] = [];
      let depth: number | null = null;
      let inHaves = false;
      const { packets } = parsePktLines(body);
      for (const packet of packets) {
        if (packet.kind === 'flush') {
          inHaves = true;
          continue;
        }
        if (packet.kind !== 'data') continue;
        const line = packet.payload.toString('utf8').replace(/\n$/, '');
        if (!inHaves) {
          if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0] as string);
          else if (line.startsWith('shallow ')) shallow.push(line.slice(8));
          else if (line.startsWith('deepen ')) depth = Number(line.slice(7));
        } else if (line.startsWith('have ')) {
          haves.push(line.slice(5));
        }
      }
      const plan = planFetch(repo, wants, haves, shallow, depth);
      const chunks: Buffer[] = [];
      if (plan.acks.length === 0) chunks.push(pktLine('NAK\n'));
      else {
        for (const ack of plan.acks) chunks.push(pktLine(`ACK ${ack}\n`));
      }
      for (const oid of plan.shallow) chunks.push(pktLine(`shallow ${oid}\n`));
      for (const oid of plan.unshallow) chunks.push(pktLine(`unshallow ${oid}\n`));
      if (plan.toSend.size > 0) {
        const pack = writePack([...plan.toSend.values()]);
        chunks.push(...sidebandPackets(pack));
      }
      chunks.push(PKT_FLUSH);
      sendRaw(res, 200, Buffer.concat(chunks), 'application/x-git-upload-pack-result');
      return true;
    }
    sendRaw(res, 400, Buffer.from('unknown command\n', 'utf8'), 'text/plain');
    return true;
  }

  if (method === 'POST' && service === 'git-receive-pack') {
    if (repo === undefined) {
      jsonError(res, 404, 'Not Found');
      return true;
    }
    const body = await readBody(req);
    let commands: Array<{ oldOid: string; newOid: string; ref: string }>;
    let packOffset: number;
    try {
      ({ commands, packOffset } = readPushCommands(body));
    } catch {
      sendRaw(res, 400, Buffer.from('bad pkt-line\n', 'utf8'), 'text/plain');
      return true;
    }
    const results: Array<{ ok: boolean; reason: string }> = [];
    let unpackOk = true;
    let unpackDetail = 'ok';
    if (packOffset < body.length) {
      try {
        const objects = readPack(body.subarray(packOffset), (oid) => repo.objects.get(oid));
        for (const [oid, object] of objects) repo.objects.set(oid, object);
      } catch (err) {
        unpackOk = false;
        unpackDetail = err instanceof Error ? err.message : 'unpack failed';
      }
    }
    for (const command of commands) {
      if (!unpackOk) {
        results.push({ ok: false, reason: 'unpack failed' });
        continue;
      }
      results.push(evalPushCommand(repo, command));
    }
    // The report is a pkt-line stream carried on sideband band 1, and it must end
    // with its own flush inside the band: the client's report reader dies on EOF,
    // and the outer flush only ends the sideband stream.
    const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}\n`];
    commands.forEach((command, index) => {
      const result = results[index] as { ok: boolean; reason: string };
      reportLines.push(result.ok ? `ok ${command.ref}\n` : `ng ${command.ref} ${result.reason}\n`);
    });
    const reportStream = Buffer.concat([...reportLines.map((line) => pktLine(line)), PKT_FLUSH]);
    const banded: Buffer[] = [...sidebandPackets(reportStream), PKT_FLUSH];
    sendRaw(res, 200, Buffer.concat(banded), 'application/x-git-receive-pack-result');
    return true;
  }

  return false;
}

// -------------------------------------------------------------------------------------------
// GraphQL v4: a small parser for the documents gh and github-mcp-server send, and an
// executor over the same store the REST surface reads.
// -------------------------------------------------------------------------------------------

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlField {
  alias: string | null;
  name: string;
  args: Array<{ name: string; value: GqlValue }>;
  selection: GqlSelection[] | null;
}

type GqlSelection = { kind: 'field'; field: GqlField } | { kind: 'fragment'; type: string; selection: GqlSelection[] };

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  variables: Array<{ name: string; defaultValue: GqlValue | null }>;
  selection: GqlSelection[];
}

class GqlParser {
  private at = 0;
  private readonly text: string;
  constructor(text: string) {
    this.text = text;
  }

  private peek(): string {
    return this.text[this.at] ?? '';
  }

  private skipSpace(): void {
    for (;;) {
      while (this.at < this.text.length && /[\s,]/.test(this.text[this.at] as string)) this.at += 1;
      if (this.text[this.at] === '#') {
        while (this.at < this.text.length && this.text[this.at] !== '\n') this.at += 1;
        continue;
      }
      return;
    }
  }

  private expect(char: string): void {
    this.skipSpace();
    if (this.text[this.at] !== char) throw new Error(`expected ${char} at ${this.at}`);
    this.at += 1;
  }

  private takeName(): string {
    this.skipSpace();
    const match = /^[A-Za-z_][A-Za-z0-9_]*/.exec(this.text.slice(this.at));
    if (match === null) throw new Error(`expected a name at ${this.at}`);
    this.at += match[0].length;
    return match[0];
  }

  private takeString(): string {
    this.skipSpace();
    if (this.text[this.at] !== '"') throw new Error(`expected a string at ${this.at}`);
    this.at += 1;
    let out = '';
    while (this.at < this.text.length) {
      const char = this.text[this.at] as string;
      if (char === '"') {
        this.at += 1;
        return out;
      }
      if (char === '\\') {
        const next = this.text[this.at + 1] as string;
        const escapes: Record<string, string> = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/' };
        out += escapes[next] ?? next;
        this.at += 2;
        continue;
      }
      out += char;
      this.at += 1;
    }
    throw new Error('unterminated string');
  }

  parseValue(): GqlValue {
    this.skipSpace();
    const char = this.peek();
    if (char === '$') {
      this.at += 1;
      return { kind: 'variable', name: this.takeName() };
    }
    if (char === '"') return { kind: 'string', value: this.takeString() };
    if (char === '[') {
      this.at += 1;
      const values: GqlValue[] = [];
      for (;;) {
        this.skipSpace();
        if (this.peek() === ']') {
          this.at += 1;
          return { kind: 'list', values };
        }
        values.push(this.parseValue());
      }
    }
    if (char === '{') {
      this.at += 1;
      const fields: Array<{ name: string; value: GqlValue }> = [];
      for (;;) {
        this.skipSpace();
        if (this.peek() === '}') {
          this.at += 1;
          return { kind: 'object', fields };
        }
        const name = this.takeName();
        this.expect(':');
        fields.push({ name, value: this.parseValue() });
      }
    }
    const word = /^[A-Za-z_][A-Za-z0-9_]*/.exec(this.text.slice(this.at));
    if (word !== null) {
      this.at += word[0].length;
      if (word[0] === 'true') return { kind: 'boolean', value: true };
      if (word[0] === 'false') return { kind: 'boolean', value: false };
      if (word[0] === 'null') return { kind: 'null' };
      return { kind: 'enum', value: word[0] };
    }
    const number = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(this.text.slice(this.at));
    if (number !== null) {
      this.at += number[0].length;
      return number[0].includes('.') || /[eE]/.test(number[0])
        ? { kind: 'float', value: Number(number[0]) }
        : { kind: 'int', value: Number(number[0]) };
    }
    throw new Error(`unexpected value at ${this.at}`);
  }

  private parseArgs(): Array<{ name: string; value: GqlValue }> {
    this.skipSpace();
    const args: Array<{ name: string; value: GqlValue }> = [];
    if (this.peek() !== '(') return args;
    this.at += 1;
    for (;;) {
      this.skipSpace();
      if (this.peek() === ')') {
        this.at += 1;
        return args;
      }
      const name = this.takeName();
      this.expect(':');
      args.push({ name, value: this.parseValue() });
    }
  }

  private skipDirectives(): void {
    for (;;) {
      this.skipSpace();
      if (this.peek() !== '@') return;
      this.at += 1;
      this.takeName();
      this.parseArgs();
    }
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const selections: GqlSelection[] = [];
    for (;;) {
      this.skipSpace();
      if (this.peek() === '}') {
        this.at += 1;
        return selections;
      }
      if (this.text.startsWith('...', this.at)) {
        this.at += 3;
        this.skipSpace();
        if (this.text.startsWith('on', this.at) && !/[A-Za-z0-9_]/.test(this.text[this.at + 2] ?? '')) {
          this.at += 2;
          const type = this.takeName();
          this.skipDirectives();
          selections.push({ kind: 'fragment', type, selection: this.parseSelectionSet() });
        } else {
          // A named fragment spread: the documents here do not use them; skip its selection.
          this.takeName();
          this.skipDirectives();
          if (this.peek() === '{') this.parseSelectionSet();
        }
        continue;
      }
      const first = this.takeName();
      this.skipSpace();
      let alias: string | null = null;
      let name = first;
      if (this.peek() === ':') {
        this.at += 1;
        alias = first;
        name = this.takeName();
      }
      const args = this.parseArgs();
      this.skipDirectives();
      this.skipSpace();
      const selection = this.peek() === '{' ? this.parseSelectionSet() : null;
      selections.push({ kind: 'field', field: { alias, name, args, selection } });
    }
  }

  private parseVariableDefinitions(): Array<{ name: string; defaultValue: GqlValue | null }> {
    this.skipSpace();
    const variables: Array<{ name: string; defaultValue: GqlValue | null }> = [];
    if (this.peek() !== '(') return variables;
    this.at += 1;
    for (;;) {
      this.skipSpace();
      if (this.peek() === ')') {
        this.at += 1;
        return variables;
      }
      this.expect('$');
      const name = this.takeName();
      this.expect(':');
      // The type: a name, possibly wrapped in [ ] and suffixed with !. Skip it wholesale.
      this.skipSpace();
      let depth = 0;
      while (this.at < this.text.length) {
        const char = this.text[this.at] as string;
        if (char === '[') depth += 1;
        else if (char === ']') depth -= 1;
        else if (char === '!' && depth === 0) {
          this.at += 1;
          break;
        } else if ((char === '=' || char === ',' || char === ')') && depth === 0) {
          break;
        }
        this.at += 1;
      }
      let defaultValue: GqlValue | null = null;
      this.skipSpace();
      if (this.peek() === '=') {
        this.at += 1;
        defaultValue = this.parseValue();
      }
      variables.push({ name, defaultValue });
    }
  }

  parseDocument(): GqlOperation[] {
    const operations: GqlOperation[] = [];
    for (;;) {
      this.skipSpace();
      if (this.at >= this.text.length) return operations;
      if (this.peek() === '{') {
        operations.push({ kind: 'query', name: null, variables: [], selection: this.parseSelectionSet() });
        continue;
      }
      const word = this.takeName();
      if (word === 'fragment') {
        this.takeName();
        this.skipDirectives();
        this.parseSelectionSet();
        continue;
      }
      if (word !== 'query' && word !== 'mutation') throw new Error(`unexpected keyword ${word}`);
      this.skipSpace();
      let name: string | null = null;
      if (/[A-Za-z_]/.test(this.peek())) name = this.takeName();
      const variables = this.parseVariableDefinitions();
      this.skipDirectives();
      operations.push({ kind: word, name, variables, selection: this.parseSelectionSet() });
    }
  }
}

function evalGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'variable':
      return variables[value.name];
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.values.map((entry) => evalGqlValue(entry, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = evalGqlValue(field.value, variables);
      return out;
    }
  }
}

function argsOf(field: GqlField, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const arg of field.args) out[arg.name] = evalGqlValue(arg.value, variables);
  return out;
}

// The introspection tables gh feature-detects.
const TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'bodyText', 'createdAt', 'updatedAt', 'url', 'author', 'comments', 'labels', 'closed', 'locked'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'createdAt', 'updatedAt', 'url', 'author', 'comments', 'additions', 'deletions', 'changedFiles', 'isDraft', 'mergedAt', 'mergeCommit'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'isPrivate', 'createdAt', 'updatedAt', 'url', 'forkCount', 'stargazerCount'],
};
const TYPE_ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'],
};

interface GqlContext {
  errors: Array<{ message: string }>;
  variables: Record<string, unknown>;
}

function unknownField(ctx: GqlContext, type: string, name: string): null {
  ctx.errors.push({ message: `Cannot query field "${name}" on type "${type}".` });
  return null;
}

function issueStateGql(issue: Issue): string {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}

function pullStateGql(pull: PullRequest): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

/** Apply a selection set to a value of a named GraphQL type; unknown fields become errors. */
function selectFields(ctx: GqlContext, type: string, value: Record<string, unknown> | null, selection: GqlSelection[] | null): Record<string, unknown> | null {
  if (value === null) return null;
  if (selection === null) return value;
  const out: Record<string, unknown> = {};
  for (const item of selection) {
    if (item.kind === 'fragment') {
      if (item.type !== type) continue;
      const merged = selectFields(ctx, type, value, item.selection);
      if (merged !== null) Object.assign(out, merged);
      continue;
    }
    const field = item.field;
    const key = field.alias ?? field.name;
    const resolved = resolveGqlField(ctx, type, value, field);
    out[key] = resolved;
  }
  return out;
}

function resolveGqlField(ctx: GqlContext, type: string, value: Record<string, unknown>, field: GqlField): unknown {
  const args = argsOf(field, ctx.variables);
  const repo = value.__repo as Repo | undefined;
  const issue = value.__issue as Issue | undefined;
  const pull = value.__pull as PullRequest | undefined;

  if (type === 'Query') {
    if (field.name === 'viewer') {
      const viewer: Record<string, unknown> = { __type: 'User', login: VIEWER_LOGIN, id: globalId('user', VIEWER_ID) };
      return selectFields(ctx, 'User', viewer, field.selection);
    }
    if (field.name === 'repository') {
      const owner = String(args.owner ?? '');
      const name = String(args.name ?? '');
      const found = findRepo(owner, name);
      if (found === undefined) return null;
      const node: Record<string, unknown> = { __type: 'Repository', __repo: found };
      return selectFields(ctx, 'Repository', node, field.selection);
    }
    if (field.name === 'node') {
      const id = String(args.id ?? '');
      const decoded = decodeGlobalId(id);
      if (decoded === null) return null;
      if (decoded.kind === 'repo') {
        const found = repoByGlobalId(id);
        if (found === undefined) return null;
        const node: Record<string, unknown> = { __type: 'Repository', __repo: found };
        return selectFields(ctx, 'Repository', node, field.selection);
      }
      return null;
    }
    if (field.name === '__type') {
      const name = String(args.name ?? '');
      const fields = TYPE_FIELDS[name];
      const enums = TYPE_ENUM_VALUES[name];
      if (fields === undefined && enums === undefined) return null;
      const node: Record<string, unknown> = {
        __type: '__Type',
        __fields: fields ?? [],
        __enums: enums ?? [],
        name,
        kind: fields !== undefined ? 'OBJECT' : 'ENUM',
      };
      return selectFields(ctx, '__Type', node, field.selection);
    }
    return unknownField(ctx, 'Query', field.name);
  }

  if (type === 'Mutation') {
    if (field.name === 'createIssue') return mutateCreateIssue(ctx, args, field);
    if (field.name === 'closeIssue') return mutateCloseIssue(ctx, args, field);
    if (field.name === 'createPullRequest') return mutateCreatePullRequest(ctx, args, field);
    if (field.name === 'mergePullRequest') return mutateMergePullRequest(ctx, args, field);
    if (field.name === 'addComment') return mutateAddComment(ctx, args, field);
    return unknownField(ctx, 'Mutation', field.name);
  }

  if (type === 'User') {
    if (field.name === 'login') return VIEWER_LOGIN;
    if (field.name === 'id') return typeof value.id === 'string' ? value.id : globalId('user', VIEWER_ID);
    return unknownField(ctx, type, field.name);
  }

  if (type === 'Repository' && repo !== undefined) {
    switch (field.name) {
      case 'id':
        return globalId('repo', repo.id);
      case 'databaseId':
        return repo.id;
      case 'name':
        return repo.name;
      case 'nameWithOwner':
        return `${repo.owner}/${repo.name}`;
      case 'owner': {
        const owner: Record<string, unknown> = { __type: 'User', login: repo.owner, id: globalId('user', VIEWER_ID) };
        return selectFields(ctx, 'User', owner, field.selection);
      }
      case 'defaultBranchRef': {
        const ref: Record<string, unknown> = { __type: 'Ref', name: repo.defaultBranch };
        return selectFields(ctx, 'Ref', ref, field.selection);
      }
      case 'viewerPermission':
        return 'ADMIN';
      case 'hasIssuesEnabled':
        return true;
      case 'description':
        return repo.description;
      case 'isPrivate':
        return repo.isPrivate;
      case 'url':
        return `https://github.com/${repo.owner}/${repo.name}`;
      case 'issue': {
        const number = Number(args.number);
        const found = repo.issues.find((entry) => entry.number === number);
        if (found === undefined) return null;
        const node: Record<string, unknown> = { __type: 'Issue', __repo: repo, __issue: found };
        return selectFields(ctx, 'Issue', node, field.selection);
      }
      case 'issues': {
        const list = issueConnection(repo, args);
        return selectFields(ctx, 'IssueConnection', list, field.selection);
      }
      case 'pullRequests': {
        const list = pullConnection(repo, args);
        return selectFields(ctx, 'PullRequestConnection', list, field.selection);
      }
      case 'pullRequest': {
        const number = Number(args.number);
        const found = repo.pulls.find((entry) => entry.number === number);
        if (found === undefined) return null;
        const node: Record<string, unknown> = { __type: 'PullRequest', __repo: repo, __pull: found };
        return selectFields(ctx, 'PullRequest', node, field.selection);
      }
      default:
        return unknownField(ctx, type, field.name);
    }
  }

  if (type === 'Issue' && issue !== undefined && repo !== undefined) {
    switch (field.name) {
      case 'id':
        return globalId('issue', repo.id, issue.number);
      case 'number':
        return issue.number;
      case 'title':
        return issue.title;
      case 'state':
        return issueStateGql(issue);
      case 'body':
        return issue.body;
      case 'createdAt':
        return issue.createdAt;
      case 'updatedAt':
        return issue.updatedAt;
      case 'url':
        return `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`;
      default:
        return unknownField(ctx, type, field.name);
    }
  }

  if (type === 'PullRequest' && pull !== undefined && repo !== undefined) {
    switch (field.name) {
      case 'id':
        return globalId('pr', repo.id, pull.number);
      case 'number':
        return pull.number;
      case 'title':
        return pull.title;
      case 'body':
        return pull.body;
      case 'state':
        return pullStateGql(pull);
      case 'merged':
        return pull.merged;
      case 'mergeable':
        return pullMergeable(repo, pull);
      case 'headRefName':
        return pull.head;
      case 'baseRefName':
        return pull.base;
      case 'files': {
        const baseTip = commitAtRef(repo, pull.base) ?? pull.baseSha;
        const headTip = commitAtRef(repo, pull.head) ?? pull.headSha;
        const files = diffFiles(repo, baseTip, headTip);
        const nodes = files.map((file) => {
          const node: Record<string, unknown> = { __type: 'ChangedFile', path: file.filename, additions: file.additions, deletions: file.deletions };
          return node;
        });
        const connection: Record<string, unknown> = { __type: 'PullRequestFilesConnection', __nodes: nodes };
        return selectFields(ctx, 'PullRequestFilesConnection', connection, field.selection);
      }
      case 'createdAt':
        return pull.createdAt;
      case 'url':
        return `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`;
      default:
        return unknownField(ctx, type, field.name);
    }
  }

  if (type === 'Ref') {
    if (field.name === 'name') return typeof value.name === 'string' ? value.name : null;
    return unknownField(ctx, type, field.name);
  }

  if (type === 'IssueConnection' || type === 'PullRequestConnection') {
    if (field.name === 'nodes') {
      const nodes = (value.__nodes as Array<Record<string, unknown>> | undefined) ?? [];
      const parentType = type === 'IssueConnection' ? 'Issue' : 'PullRequest';
      return nodes.map((node) => selectFields(ctx, parentType, node, field.selection));
    }
    if (field.name === 'pageInfo') {
      const pageInfo: Record<string, unknown> = {
        __type: 'PageInfo',
        hasNextPage: value.__hasNextPage ?? false,
        endCursor: value.__endCursor ?? null,
        hasPreviousPage: false,
        startCursor: value.__startCursor ?? null,
      };
      return selectFields(ctx, 'PageInfo', pageInfo, field.selection);
    }
    if (field.name === 'totalCount') return (value.__nodes as unknown[] | undefined)?.length ?? 0;
    return unknownField(ctx, type, field.name);
  }

  if (type === 'PullRequestFilesConnection') {
    if (field.name === 'nodes') {
      const nodes = (value.__nodes as Array<Record<string, unknown>> | undefined) ?? [];
      return nodes.map((node) => selectFields(ctx, 'ChangedFile', node, field.selection));
    }
    return unknownField(ctx, type, field.name);
  }

  if (type === 'ChangedFile') {
    if (field.name === 'path') return typeof value.path === 'string' ? value.path : null;
    if (field.name === 'additions') return typeof value.additions === 'number' ? value.additions : 0;
    if (field.name === 'deletions') return typeof value.deletions === 'number' ? value.deletions : 0;
    return unknownField(ctx, type, field.name);
  }

  if (type === 'PageInfo') {
    if (field.name === 'hasNextPage') return value.hasNextPage ?? false;
    if (field.name === 'endCursor') return value.endCursor ?? null;
    if (field.name === 'hasPreviousPage') return value.hasPreviousPage ?? false;
    if (field.name === 'startCursor') return value.startCursor ?? null;
    return unknownField(ctx, type, field.name);
  }

  if (type === '__Type') {
    if (field.name === 'fields') {
      const names = (value.__fields as string[] | undefined) ?? [];
      return names.map((name) => {
        const node: Record<string, unknown> = { __type: '__Field', name };
        return selectFields(ctx, '__Field', node, field.selection);
      });
    }
    if (field.name === 'enumValues') {
      const names = (value.__enums as string[] | undefined) ?? [];
      return names.map((name) => {
        const node: Record<string, unknown> = { __type: '__EnumValue', name };
        return selectFields(ctx, '__EnumValue', node, field.selection);
      });
    }
    if (field.name === 'name') return typeof value.name === 'string' ? value.name : null;
    if (field.name === 'kind') return typeof value.kind === 'string' ? value.kind : null;
    return unknownField(ctx, type, field.name);
  }

  if (type === '__Field' || type === '__EnumValue') {
    if (field.name === 'name') return typeof value.name === 'string' ? value.name : null;
    return unknownField(ctx, type, field.name);
  }

  if (type === 'IssueCreatePayload' || type === 'IssueClosePayload') {
    if (field.name === 'issue') {
      const node = value.__issueNode as Record<string, unknown> | undefined;
      if (node === undefined) return null;
      return selectFields(ctx, 'Issue', node, field.selection);
    }
    return unknownField(ctx, type, field.name);
  }

  if (type === 'PullRequestCreatePayload' || type === 'PullRequestMergePayload') {
    if (field.name === 'pullRequest') {
      const node = value.__pullNode as Record<string, unknown> | undefined;
      if (node === undefined) return null;
      return selectFields(ctx, 'PullRequest', node, field.selection);
    }
    return unknownField(ctx, type, field.name);
  }

  if (type === 'AddCommentPayload') {
    if (field.name === 'commentEdge') {
      const edge = value.__edge as Record<string, unknown> | undefined;
      if (edge === undefined) return null;
      return selectFields(ctx, 'CommentEdge', edge, field.selection);
    }
    return unknownField(ctx, type, field.name);
  }

  if (type === 'CommentEdge') {
    if (field.name === 'node') {
      const node = value.__node as Record<string, unknown> | undefined;
      if (node === undefined) return null;
      return selectFields(ctx, 'Comment', node, field.selection);
    }
    return unknownField(ctx, type, field.name);
  }

  if (type === 'Comment') {
    if (field.name === 'id') return typeof value.id === 'string' ? value.id : null;
    if (field.name === 'body') return typeof value.body === 'string' ? value.body : null;
    return unknownField(ctx, type, field.name);
  }

  return unknownField(ctx, type, field.name);
}

/** An issues connection: states filter, CREATED_AT order, cursor paging. */
function issueConnection(repo: Repo, args: Record<string, unknown>): Record<string, unknown> {
  const states = Array.isArray(args.states) ? (args.states as unknown[]).map(String) : null;
  const orderBy = (args.orderBy as Record<string, unknown> | undefined) ?? {};
  const direction = String(orderBy.direction ?? 'DESC');
  let issues = [...repo.issues];
  if (states !== null) {
    issues = issues.filter((issue) => states.includes(issueStateGql(issue)));
  }
  issues.sort((a, b) => (direction === 'ASC' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
  const after = typeof args.after === 'string' && args.after !== '' ? Number(b64urlDecode(args.after).split(':')[1]) : null;
  if (after !== null && Number.isInteger(after)) {
    issues = issues.filter((issue) => (direction === 'ASC' ? issue.number > after : issue.number < after));
  }
  const first = typeof args.first === 'number' ? args.first : issues.length;
  const page = issues.slice(0, first);
  const nodes = page.map((issue) => {
    const node: Record<string, unknown> = { __type: 'Issue', __repo: repo, __issue: issue };
    return node;
  });
  const hasNextPage = issues.length > page.length;
  const last = page[page.length - 1];
  return {
    __type: 'IssueConnection',
    __nodes: nodes,
    __hasNextPage: hasNextPage,
    __endCursor: last === undefined ? null : b64urlEncode(`cursor:${last.number}`),
    __startCursor: page[0] === undefined ? null : b64urlEncode(`cursor:${page[0].number}`),
  };
}

/** A pull requests connection: states filter, creation order. */
function pullConnection(repo: Repo, args: Record<string, unknown>): Record<string, unknown> {
  const states = Array.isArray(args.states) ? (args.states as unknown[]).map(String) : null;
  let pulls = [...repo.pulls];
  if (states !== null) {
    pulls = pulls.filter((pull) => states.includes(pullStateGql(pull)));
  } else {
    pulls = pulls.filter((pull) => pull.state === 'open');
  }
  pulls.sort((a, b) => b.createdSeq - a.createdSeq);
  const first = typeof args.first === 'number' ? args.first : pulls.length;
  const page = pulls.slice(0, first);
  const nodes = page.map((pull) => {
    const node: Record<string, unknown> = { __type: 'PullRequest', __repo: repo, __pull: pull };
    return node;
  });
  return {
    __type: 'PullRequestConnection',
    __nodes: nodes,
    __hasNextPage: pulls.length > page.length,
    __endCursor: null,
    __startCursor: null,
  };
}

// -------------------------------------------------------------------------------------------
// GraphQL mutations (each answers its payload object, or null with an error)
// -------------------------------------------------------------------------------------------

function issueNode(repo: Repo, issue: Issue): Record<string, unknown> {
  return { __type: 'Issue', __repo: repo, __issue: issue };
}

function pullNode(repo: Repo, pull: PullRequest): Record<string, unknown> {
  return { __type: 'PullRequest', __repo: repo, __pull: pull };
}

function mutateCreateIssue(ctx: GqlContext, args: Record<string, unknown>, field: GqlField): unknown {
  const input = (args.input as Record<string, unknown> | undefined) ?? {};
  const repo = typeof input.repositoryId === 'string' ? repoByGlobalId(input.repositoryId) : undefined;
  if (repo === undefined) {
    ctx.errors.push({ message: 'Could not resolve to a Repository with the global id.' });
    return null;
  }
  const title = typeof input.title === 'string' ? input.title : '';
  const body = typeof input.body === 'string' ? input.body : '';
  const issue = createIssueRecord(repo, title, body, []);
  const payload: Record<string, unknown> = { __type: 'IssueCreatePayload', __issueNode: issueNode(repo, issue) };
  return selectFields(ctx, 'IssueCreatePayload', payload, field.selection);
}

function mutateCloseIssue(ctx: GqlContext, args: Record<string, unknown>, field: GqlField): unknown {
  const input = (args.input as Record<string, unknown> | undefined) ?? {};
  const decoded = typeof input.issueId === 'string' ? decodeGlobalId(input.issueId) : null;
  if (decoded === null || decoded.kind !== 'issue') {
    ctx.errors.push({ message: 'Could not resolve to an Issue with the global id.' });
    return null;
  }
  const repo = repoByGlobalId(globalId('repo', Number(decoded.parts[0])));
  const issue = repo?.issues.find((entry) => entry.number === Number(decoded.parts[1]));
  if (repo === undefined || issue === undefined) {
    ctx.errors.push({ message: 'Could not resolve to an Issue with the global id.' });
    return null;
  }
  issue.state = 'closed';
  issue.updatedAt = nowIso();
  const payload: Record<string, unknown> = { __type: 'IssueClosePayload', __issueNode: issueNode(repo, issue) };
  return selectFields(ctx, 'IssueClosePayload', payload, field.selection);
}

function mutateCreatePullRequest(ctx: GqlContext, args: Record<string, unknown>, field: GqlField): unknown {
  const input = (args.input as Record<string, unknown> | undefined) ?? {};
  const repo = typeof input.repositoryId === 'string' ? repoByGlobalId(input.repositoryId) : undefined;
  if (repo === undefined) {
    ctx.errors.push({ message: 'Could not resolve to a Repository with the global id.' });
    return null;
  }
  const head = typeof input.headRefName === 'string' ? input.headRefName : '';
  const base = typeof input.baseRefName === 'string' ? input.baseRefName : '';
  const title = typeof input.title === 'string' ? input.title : '';
  const body = typeof input.body === 'string' ? input.body : '';
  const headSha = commitAtRef(repo, head);
  const baseSha = commitAtRef(repo, base);
  if (headSha === null || baseSha === null) {
    ctx.errors.push({ message: 'Head or base ref does not exist.' });
    return null;
  }
  const pull = createPullRecord(repo, title, body, head, base, headSha, baseSha);
  const payload: Record<string, unknown> = { __type: 'PullRequestCreatePayload', __pullNode: pullNode(repo, pull) };
  return selectFields(ctx, 'PullRequestCreatePayload', payload, field.selection);
}

function mutateMergePullRequest(ctx: GqlContext, args: Record<string, unknown>, field: GqlField): unknown {
  const input = (args.input as Record<string, unknown> | undefined) ?? {};
  const decoded = typeof input.pullRequestId === 'string' ? decodeGlobalId(input.pullRequestId) : null;
  if (decoded === null || decoded.kind !== 'pr') {
    ctx.errors.push({ message: 'Could not resolve to a PullRequest with the global id.' });
    return null;
  }
  const repo = repoByGlobalId(globalId('repo', Number(decoded.parts[0])));
  const pull = repo?.pulls.find((entry) => entry.number === Number(decoded.parts[1]));
  if (repo === undefined || pull === undefined) {
    ctx.errors.push({ message: 'Could not resolve to a PullRequest with the global id.' });
    return null;
  }
  const method = typeof input.mergeMethod === 'string' ? input.mergeMethod.toLowerCase() : 'squash';
  const merged = mergePullRequest(repo, pull, method);
  if (!merged.ok) {
    ctx.errors.push({ message: merged.message });
    return null;
  }
  const payload: Record<string, unknown> = { __type: 'PullRequestMergePayload', __pullNode: pullNode(repo, pull) };
  return selectFields(ctx, 'PullRequestMergePayload', payload, field.selection);
}

function mutateAddComment(ctx: GqlContext, args: Record<string, unknown>, field: GqlField): unknown {
  const input = (args.input as Record<string, unknown> | undefined) ?? {};
  const decoded = typeof input.subjectId === 'string' ? decodeGlobalId(input.subjectId) : null;
  if (decoded === null || decoded.kind !== 'issue') {
    ctx.errors.push({ message: 'Could not resolve to an Issue with the global id.' });
    return null;
  }
  const repo = repoByGlobalId(globalId('repo', Number(decoded.parts[0])));
  const issue = repo?.issues.find((entry) => entry.number === Number(decoded.parts[1]));
  if (repo === undefined || issue === undefined) {
    ctx.errors.push({ message: 'Could not resolve to an Issue with the global id.' });
    return null;
  }
  const body = typeof input.body === 'string' ? input.body : '';
  const comment: IssueComment = { id: repo.nextCommentId, body, createdAt: nowIso() };
  repo.nextCommentId += 1;
  issue.comments.push(comment);
  const node: Record<string, unknown> = {
    __type: 'Comment',
    id: globalId('comment', repo.id, issue.number, comment.id),
    body,
  };
  const edge: Record<string, unknown> = { __type: 'CommentEdge', __node: node };
  const payload: Record<string, unknown> = { __type: 'AddCommentPayload', __edge: edge };
  return selectFields(ctx, 'AddCommentPayload', payload, field.selection);
}

/** Execute one parsed operation; answers the GraphQL result object. */
function executeGqlOperation(operation: GqlOperation, variables: Record<string, unknown>): Record<string, unknown> {
  const ctx: GqlContext = { errors: [], variables };
  for (const variable of operation.variables) {
    if (!(variable.name in ctx.variables) && variable.defaultValue !== null) {
      ctx.variables[variable.name] = evalGqlValue(variable.defaultValue, variables);
    }
  }
  const rootType = operation.kind === 'mutation' ? 'Mutation' : 'Query';
  const root: Record<string, unknown> = { __type: rootType };
  const data = selectFields(ctx, rootType, root, operation.selection) ?? {};
  const result: Record<string, unknown> = { data };
  if (ctx.errors.length > 0) result.errors = ctx.errors;
  return result;
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    jsonError(res, 400, 'Invalid JSON body');
    return true;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (entry === null || typeof entry !== 'object') return { data: null, errors: [{ message: 'Request must be an object.' }] };
    const body = entry as Record<string, unknown>;
    const query = typeof body.query === 'string' ? body.query : '';
    const variables = (body.variables as Record<string, unknown> | undefined) ?? {};
    const operationName = typeof body.operationName === 'string' ? body.operationName : null;
    let operations: GqlOperation[];
    try {
      operations = new GqlParser(query).parseDocument();
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : 'Syntax error' }] };
    }
    if (operations.length === 0) return { data: null, errors: [{ message: 'No operation in document.' }] };
    let operation = operations[0];
    if (operationName !== null) {
      const named = operations.find((entry) => entry.name === operationName);
      if (named !== undefined) operation = named;
    }
    return executeGqlOperation(operation as GqlOperation, variables);
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map(runOne));
    return true;
  }
  sendJson(res, 200, runOne(parsed));
  return true;
}

// -------------------------------------------------------------------------------------------
// MCP over streamable HTTP: the 2026-07-28 era (server/discover, no handshake), JSON-RPC 2.0
// -------------------------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  properties: Record<string, Record<string, unknown>>;
  required: string[];
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    properties: {
      name: { type: 'string', description: 'The repository name.' },
      description: { type: 'string', description: 'A short description of the repository.' },
      private: { type: 'boolean', description: 'Whether the repository is private.' },
    },
    required: ['name'],
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The issue title.' },
      body: { type: 'string', description: 'The issue body.' },
    },
    required: ['owner', 'repo', 'title'],
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'open, closed or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The pull request title.' },
      body: { type: 'string', description: 'The pull request body.' },
      head: { type: 'string', description: 'The head branch name.' },
      base: { type: 'string', description: 'The base branch name.' },
    },
    required: ['owner', 'repo', 'title', 'head', 'base'],
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit onto its base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      pull_number: { type: 'integer', description: 'The pull request number.' },
    },
    required: ['owner', 'repo', 'pull_number'],
  },
];

function mcpToolsList(): Array<Record<string, unknown>> {
  return MCP_TOOLS.map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: {
      type: 'object',
      properties: tool.properties,
      required: tool.required,
      additionalProperties: false,
    },
  }));
}

function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, result };
}

function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function mcpToolResult(payload: unknown): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    structuredContent: payload,
    isError: false,
  };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function missingArg(args: Record<string, unknown>, name: string): boolean {
  const value = args[name];
  return value === undefined || value === null || value === '';
}

function callMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const tool = MCP_TOOLS.find((entry) => entry.name === name);
  if (tool === undefined) return mcpToolError(`Unknown tool: ${name}`);
  for (const required of tool.required) {
    if (missingArg(args, required)) return mcpToolError(`Missing required argument: ${required}`);
  }
  if (name === 'create_repo') {
    const repoName = String(args.name);
    if (store.repos.has(repoName)) return mcpToolError(`Repository ${repoName} already exists`);
    const repo = createRepoRecord(repoName, args.private === true, typeof args.description === 'string' ? args.description : '');
    return mcpToolResult(repoJson(repo));
  }
  const owner = String(args.owner);
  const repoName = String(args.repo);
  const repo = findRepo(owner, repoName);
  if (repo === undefined) return mcpToolError(`Repository ${owner}/${repoName} not found`);
  if (name === 'get_repo') return mcpToolResult(repoJson(repo));
  if (name === 'create_issue') {
    const issue = createIssueRecord(repo, String(args.title), typeof args.body === 'string' ? args.body : '', []);
    return mcpToolResult(issueJson(repo, issue));
  }
  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    const issues = state === 'all' ? repo.issues : repo.issues.filter((issue) => issue.state === state);
    return mcpToolResult(issues.map((issue) => issueJson(repo, issue)));
  }
  if (name === 'create_pull_request') {
    const head = String(args.head);
    const base = String(args.base);
    const headSha = commitAtRef(repo, head);
    const baseSha = commitAtRef(repo, base);
    if (headSha === null || baseSha === null) return mcpToolError('head or base branch does not exist');
    const pull = createPullRecord(repo, String(args.title), typeof args.body === 'string' ? args.body : '', head, base, headSha, baseSha);
    return mcpToolResult(pullJson(repo, pull));
  }
  if (name === 'merge_pull_request') {
    const number = Number(args.pull_number);
    const pull = repo.pulls.find((entry) => entry.number === number);
    if (pull === undefined) return mcpToolError(`Pull request #${args.pull_number} not found`);
    if (pull.merged || pull.state !== 'open') return mcpToolError('Pull request is already merged or closed');
    const merged = mergePullRequest(repo, pull, 'squash');
    if (!merged.ok) return mcpToolError(merged.message);
    return mcpToolResult(pullJson(repo, pull));
  }
  return mcpToolError(`Unknown tool: ${name}`);
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  if (req.method === 'DELETE') {
    sendNoContent(res, 204);
    return true;
  }
  if (req.method !== 'POST') {
    jsonError(res, 404, 'Not Found');
    return true;
  }
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    // A body that is not JSON: HTTP 400 with a JSON-RPC parse error, keeping the id when readable.
    const idMatch = /"id"\s*:\s*("[^"]*"|\d+)/.exec(raw.toString('utf8'));
    const id = idMatch === null ? null : idMatch[1]?.startsWith('"') ? (idMatch[1] as string).slice(1, -1) : Number(idMatch[1]);
    sendJson(res, 400, mcpError(id, -32700, 'Parse error'));
    return true;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      return mcpError(null, -32600, 'Invalid Request');
    }
    const body = entry as Record<string, unknown>;
    const id = body.id ?? null;
    const method = typeof body.method === 'string' ? body.method : '';
    const params = (body.params as Record<string, unknown> | undefined) ?? {};
    if (method === 'server/discover') {
      return mcpResult(id, {
        supportedVersions: ['2026-07-28'],
        protocolVersion: '2026-07-28',
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION } },
      });
    }
    if (method === 'initialize') {
      const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
      return mcpResult(id, {
        protocolVersion: requested,
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      });
    }
    if (method === 'notifications/initialized') {
      return mcpResult(id, {});
    }
    if (method === 'tools/list') {
      return mcpResult(id, { tools: mcpToolsList() });
    }
    if (method === 'tools/call') {
      const toolName = typeof params.name === 'string' ? params.name : '';
      const args = (params.arguments as Record<string, unknown> | undefined) ?? {};
      const known = MCP_TOOLS.some((entry) => entry.name === toolName);
      if (!known) return mcpError(id, -32601, `Method not found: ${toolName}`);
      return mcpResult(id, callMcpTool(toolName, args));
    }
    if (method.startsWith('notifications/')) {
      return mcpResult(id, {});
    }
    return mcpError(id, -32601, `Method not found: ${method}`);
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map(runOne));
    return true;
  }
  const body = parsed as Record<string, unknown>;
  // A notification (no id) is answered 202 with no body.
  if (typeof body.method === 'string' && body.method.startsWith('notifications/') && body.id === undefined) {
    sendNoContent(res, 202);
    return true;
  }
  sendJson(res, 200, runOne(parsed));
  return true;
}

// -------------------------------------------------------------------------------------------
// The router and the server
// -------------------------------------------------------------------------------------------

/** Build the server. It binds nothing until the caller listens; the entry listens on an ephemeral port. */
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const route = parseRoute(req);
        const method = req.method ?? 'GET';
        const path = `/${route.segments.join('/')}`;

        // The env's boot check calls this twice: 200 {"ok":true}. It takes no token.
        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }

        // Everything else is an API call and presents the shop token.
        if (!authed(req)) {
          // Unknown routes stay 404 even without a token; known API routes refuse 401.
          const known =
            path === '/api/graphql' ||
            path === '/mcp' ||
            path.startsWith('/api/v3') ||
            (route.segments.length >= 2 && (route.segments[1] as string).endsWith('.git'));
          if (known) {
            // A WWW-Authenticate challenge lets a plain git client retry with its
            // credentials instead of failing on the first 401.
            sendJson(res, 401, { message: 'Unauthorized' }, { 'www-authenticate': 'Basic realm="forge"' });
            return;
          }
          jsonError(res, 404, 'Not Found');
          return;
        }

        if (method === 'POST' && path === '/api/graphql') {
          await handleGraphql(req, res);
          return;
        }
        if (path === '/mcp') {
          await handleMcp(req, res);
          return;
        }
        if (await handleRest(req, res, route)) return;
        if (await handleGit(req, res, route)) return;

        // Everything else, every method: GitHub's 404 body.
        jsonError(res, 404, 'Not Found');
      } catch (err) {
        process.stderr.write(`[forge] request failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
        if (!res.headersSent) jsonError(res, 500, 'Internal Server Error');
        else res.end();
      }
    })();
  });
}
