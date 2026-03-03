/**
 * E2E tests for the Cerberus backend server API
 */
'use strict';

const http = require('http');
const assert = require('assert');

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

function request(method, path, body) {
    return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const options = {
            hostname: 'localhost',
            port: 5000,
            path,
            method,
            headers: {
                'Content-Type': 'application/json',
                ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
            },
        };
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => (data += chunk));
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
                catch { resolve({ status: res.statusCode, body: data }); }
            });
        });
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

function requestRaw(path, contentType, rawBody) {
    return new Promise((resolve, reject) => {
        const payload = Buffer.from(rawBody);
        const options = {
            hostname: 'localhost', port: 5000, path, method: 'POST',
            headers: { 'Content-Type': contentType, 'Content-Length': payload.length },
        };
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
                catch { resolve({ status: res.statusCode, body: data }); }
            });
        });
        req.on('error', reject);
        req.write(payload); req.end();
    });
}

let passed = 0;
let failed = 0;

async function test(name, fn) {
    try {
        await fn();
        console.log(`  ✅ ${name}`);
        passed++;
    } catch (err) {
        console.log(`  ❌ ${name}`);
        console.log(`     ${err.message}`);
        failed++;
    }
}

// ──────────────────────────────────────────────
// Main
// ──────────────────────────────────────────────

async function main() {
    // Start server silently
    const origLog = console.log;
    process.env.NODE_ENV = 'test';
    const app = require('../server.js');
    console.log = origLog;

    // Give server a moment to bind
    await new Promise(r => setTimeout(r, 600));

    console.log('\n🔍 Cerberus Server E2E Tests\n');

    // ── Health ────────────────────────────────
    console.log('── GET /api/health ──');

    await test('returns 200 with { status: "ok" }', async () => {
        const res = await request('GET', '/api/health');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.status, 'ok');
    });

    // ── /api/patch-code ───────────────────────
    console.log('\n── POST /api/patch-code ──');

    await test('400 on non-JSON content-type', async () => {
        const res = await requestRaw('/api/patch-code', 'text/plain', 'hello');
        assert.strictEqual(res.status, 400);
        assert.ok(res.body.error);
    });

    await test('400 when "code" field is missing', async () => {
        const res = await request('POST', '/api/patch-code', { notCode: 'hello' });
        assert.strictEqual(res.status, 400);
        assert.match(res.body.message, /code/i);
    });

    await test('400 when "code" field is not a string', async () => {
        const res = await request('POST', '/api/patch-code', { code: 12345 });
        assert.strictEqual(res.status, 400);
        assert.match(res.body.message, /code/i);
    });

    // ── /api/scan ─────────────────────────────
    console.log('\n── POST /api/scan ──');

    await test('400 on non-JSON content-type', async () => {
        const res = await requestRaw('/api/scan', 'text/plain', 'hello');
        assert.strictEqual(res.status, 400);
    });

    await test('400 when "path" field is missing', async () => {
        const res = await request('POST', '/api/scan', { notPath: '/tmp' });
        assert.strictEqual(res.status, 400);
        assert.match(res.body.message, /path/i);
    });

    await test('400 when path does not exist', async () => {
        const res = await request('POST', '/api/scan', { path: '/tmp/cerberus_nonexistent_dir_xyz123' });
        assert.strictEqual(res.status, 400);
        assert.match(res.body.error, /path/i);
    });

    await test('400 when path is a file not a directory', async () => {
        const res = await request('POST', '/api/scan', { path: '/etc/hosts' });
        assert.strictEqual(res.status, 400);
    });

    // ── /api/scan-file ────────────────────────
    console.log('\n── POST /api/scan-file ──');

    await test('400 when "code" field is missing', async () => {
        const res = await request('POST', '/api/scan-file', { path: '/tmp/foo.py' });
        assert.strictEqual(res.status, 400);
        assert.match(res.body.message, /code/i);
    });

    await test('400 when fields are not strings', async () => {
        const res = await request('POST', '/api/scan-file', { path: 123, code: 456 });
        assert.strictEqual(res.status, 400);
    });

    await test('400 on non-JSON content-type', async () => {
        const res = await requestRaw('/api/scan-file', 'text/plain', 'hello');
        assert.strictEqual(res.status, 400);
    });

    // ──────────────────────────────────────────
    // Summary
    // ──────────────────────────────────────────
    console.log(`\n${'─'.repeat(40)}`);
    const total = passed + failed;
    console.log(`Results: ${passed}/${total} passed${failed > 0 ? `, ${failed} failed` : ''}`);

    if (failed > 0) {
        process.exit(1);
    } else {
        console.log('All tests passed! 🎉\n');
        process.exit(0);
    }
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
