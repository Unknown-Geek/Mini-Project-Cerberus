'use strict';

/**
 * Simulates exactly what the Cerberus VS Code extension does:
 * reads a file and POSTs it to /api/scan-file, then prints results.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const FILE_TO_SCAN = process.argv[2] || './test_vulnerable.py';
const SERVER_PORT = 5000;

function scanFile(filePath) {
    return new Promise((resolve, reject) => {
        const code = fs.readFileSync(filePath, 'utf-8');
        const payload = JSON.stringify({ path: path.resolve(filePath), code });
        const options = {
            hostname: 'localhost',
            port: SERVER_PORT,
            path: '/api/scan-file',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
            },
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => (data += chunk));
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
                catch (e) { resolve({ status: res.statusCode, body: data }); }
            });
        });
        req.on('error', reject);
        req.setTimeout(130000); // match N8N_TIMEOUT_SECONDS=120
        req.write(payload);
        req.end();
    });
}

async function main() {
    // Start server silently
    const origLog = console.log;
    require('./server/server.js');
    await new Promise(r => setTimeout(r, 600));
    console.log = origLog;

    const absPath = path.resolve(FILE_TO_SCAN);
    console.log(`\n🔍 Cerberus Extension — Scanning: ${path.basename(absPath)}`);
    console.log(`   Path: ${absPath}`);
    console.log('   Sending to backend... (this may take up to 2 minutes)\n');

    const start = Date.now();
    try {
        const res = await scanFile(FILE_TO_SCAN);
        const elapsed = ((Date.now() - start) / 1000).toFixed(1);

        if (res.status !== 200) {
            console.error(`❌ Server error ${res.status}:`, JSON.stringify(res.body, null, 2));
            process.exit(1);
        }

        const { vulnerabilities } = res.body;
        const analyzed = vulnerabilities.filter(v => v.status === 'analyzed');
        const errors = vulnerabilities.filter(v => v.status === 'error');

        console.log(`⏱️  Completed in ${elapsed}s`);
        console.log(`📊 Results: ${analyzed.length} analysed, ${errors.length} errors\n`);

        if (analyzed.length > 0) {
            console.log('✅ Vulnerability analysis complete!');
            console.log('─'.repeat(60));
            for (const v of analyzed) {
                console.log(`\nFile: ${path.basename(v.file)}`);
                if (v.result) {
                    // Show first 800 chars of the corrected code
                    const preview = v.result.substring(0, 800);
                    console.log('\n📝 Corrected code preview:\n');
                    console.log(preview + (v.result.length > 800 ? '\n... (truncated)' : ''));
                }
            }
        } else if (errors.length > 0) {
            console.log('⚠️  Analysis returned errors:');
            for (const e of errors) {
                console.log(`  • ${e.error}`);
            }
        } else {
            console.log('ℹ️  No results returned.');
        }
    } catch (err) {
        console.error('❌ Failed to reach server:', err.message);
        process.exit(1);
    }

    process.exit(0);
}

main();
