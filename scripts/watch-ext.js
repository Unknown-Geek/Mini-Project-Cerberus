#!/usr/bin/env node
/**
 * watch-ext.js
 * Watches src/ and package.json for changes, then automatically:
 *   1. Compiles TypeScript  (npm run compile)
 *   2. Packages the extension  (vsce package)
 *   3. Reinstalls into VS Code  (code --install-extension)
 *
 * Usage:
 *   node scripts/watch-ext.js
 *   npm run dev:ext
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const WATCH_DIRS = [path.join(ROOT, 'src')];
const WATCH_FILES = [path.join(ROOT, 'package.json')];
const VSIX = 'cerberus-0.0.1.vsix';
const DEBOUNCE_MS = 800;

let debounceTimer = null;
let building = false;

// ── Helpers ──────────────────────────────────────────────────────────────────

function log(msg) {
  console.log(`[watch-ext] ${new Date().toLocaleTimeString()}  ${msg}`);
}

function run(cmd, label) {
  log(`▶ ${label}`);
  try {
    execSync(cmd, { cwd: ROOT, stdio: 'inherit' });
    return true;
  } catch {
    log(`✖ ${label} failed`);
    return false;
  }
}

// ── Build pipeline ────────────────────────────────────────────────────────────

async function buildAndReinstall(changedFile) {
  if (building) {
    log(`(skipping — build already in progress)`);
    return;
  }
  building = true;

  console.log('\n' + '─'.repeat(60));
  log(`Change detected: ${path.relative(ROOT, changedFile)}`);

  const ok1 = run('npm run compile', 'TypeScript compile');
  if (!ok1) { building = false; return; }

  const ok2 = run(`npx @vscode/vsce package --allow-missing-repository --no-update-package-json`, 'vsce package');
  if (!ok2) { building = false; return; }

  const ok3 = run(`code --install-extension ${VSIX}`, 'Install .vsix');
  if (ok3) {
    log('✔ Done — reload the Extension Development Host window (Ctrl+R / Cmd+R) to pick up changes.');
  }

  console.log('─'.repeat(60) + '\n');
  building = false;
}

// ── Watcher ───────────────────────────────────────────────────────────────────

function scheduleRebuild(filePath) {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => buildAndReinstall(filePath), DEBOUNCE_MS);
}

function watchDir(dir) {
  if (!fs.existsSync(dir)) return;
  fs.watch(dir, { recursive: true }, (eventType, filename) => {
    if (!filename) return;
    // Only care about TypeScript source files
    if (!filename.endsWith('.ts')) return;
    scheduleRebuild(path.join(dir, filename));
  });
  log(`Watching ${path.relative(ROOT, dir)}/**/*.ts`);
}

function watchFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  fs.watch(filePath, () => scheduleRebuild(filePath));
  log(`Watching ${path.relative(ROOT, filePath)}`);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log('Starting extension watcher…');
log(`VSIX target: ${VSIX}`);
console.log('');

WATCH_DIRS.forEach(watchDir);
WATCH_FILES.forEach(watchFile);

// Do an initial build so the installed extension is always in sync on start
buildAndReinstall(path.join(ROOT, 'src', 'extension.ts'));

process.on('SIGINT', () => {
  log('Stopped.');
  process.exit(0);
});
