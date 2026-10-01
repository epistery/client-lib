// The record helpers, over a fake facade.   node client-lib/records.test.mjs
import { listRecords, nextNumbered, tombstone, stamp, newId, isDeleted, isSealed } from './records.mjs';
let failures = 0; const check = (c, m) => c ? console.log('  ok  : ' + m) : (console.log('  FAIL: ' + m), failures++);
const files = { 'post-1.json': { id: 1, from: '0xa', timestamp: 1 }, 'post-2.json': { id: 2, from: '0xb', timestamp: 2, _deleted: true }, 'post-10.json': { id: 10 }, 'entry-ab.json': { id: 'ab' }, 'post-3.json': 'broken' };
const storage = { list: async () => Object.keys(files).map((path) => ({ path })), readJSON: async (p) => { if (files[p] === 'broken') throw new Error('bad'); return files[p] ?? null; } };
const RE = /^post-(\d+)\.json$/;
const live = await listRecords(storage, RE);
check(live.map((r) => r.record.id).sort((a, b) => a - b).join(',') === '1,10', 'listRecords: matches the name, drops the tombstone, skips the unreadable');
check(live.find((r) => r.record.id === 10).match[1] === '10', 'listRecords: the match is handed back');
check(nextNumbered(await storage.list(), RE) === 11, 'nextNumbered: max + 1 across the series');
check(nextNumbered([], RE) === 1, 'nextNumbered: an empty series starts at 1');
const t = tombstone({ id: 7, from: '0xa', timestamp: 9, iv: 'x', ciphertext: 'y' }, '0xme');
check(t.id === 7 && t.from === '0xa' && t.timestamp === 9 && t._deleted === true && t._deletedBy === '0xme' && !('iv' in t) && isDeleted(t), 'tombstone: identity kept, content gone, marker set');
const s = stamp({ a: 1 }, '0xme');
check(s.a === 1 && s._modifiedBy === '0xme' && Number.isInteger(s._modified), 'stamp: modified now, by');
check(/^[0-9a-f]{24}$/.test(newId()) && newId() !== newId(), 'newId: 24 hex, unique');
check(isSealed({ iv: 'a', ciphertext: 'b' }) && !isSealed({ text: 'x' }), 'isSealed is sealed.mjs\'s');
console.log(failures ? `RECORDS FAIL — ${failures}` : 'RECORDS PASS'); process.exit(failures ? 1 : 0);
