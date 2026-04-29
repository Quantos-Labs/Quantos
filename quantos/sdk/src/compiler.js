/**
 * Solang Compiler Wrapper
 * 
 * Finds and invokes Solang to compile .sol → .wasm (Polkadot target).
 */

const { execFileSync, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const SOLANG_CANDIDATES = [
  'solang',
  '/tmp/solang',
  '/usr/local/bin/solang',
  '/opt/homebrew/bin/solang',
  path.join(os.homedir(), '.cargo/bin/solang'),
];

function findSolang() {
  for (const candidate of SOLANG_CANDIDATES) {
    try {
      execSync(`${candidate} --version`, { stdio: 'pipe' });
      return candidate;
    } catch {}
  }
  return null;
}

function getSolangVersion(solangPath) {
  try {
    return execSync(`${solangPath} --version`, { encoding: 'utf-8' }).trim();
  } catch {
    return 'unknown';
  }
}

/**
 * Compile a Solidity file to WASM.
 * @param {string} solFile - Path to .sol file
 * @param {string} [outDir] - Output directory (default: same dir as sol file)
 * @returns {{ success: boolean, wasmPath?: string, abiPath?: string, contractName?: string, wasmSize?: number, errors?: string[] }}
 */
function compile(solFile, outDir) {
  const solangPath = findSolang();
  if (!solangPath) {
    return { success: false, errors: ['Solang not found. Install: cargo install solang'] };
  }

  const absPath = path.resolve(solFile);
  if (!fs.existsSync(absPath)) {
    return { success: false, errors: [`File not found: ${absPath}`] };
  }

  const output = outDir ? path.resolve(outDir) : path.join(path.dirname(absPath), 'build');
  if (!fs.existsSync(output)) fs.mkdirSync(output, { recursive: true });

  const args = ['compile', absPath, '--target', 'polkadot', '--output', output];

  try {
    execFileSync(solangPath, args, { timeout: 60000, stdio: 'pipe' });
  } catch (e) {
    const stderr = e.stderr ? e.stderr.toString() : '';
    const stdout = e.stdout ? e.stdout.toString() : '';
    const errors = [];
    for (const line of (stderr + '\n' + stdout).split('\n')) {
      if (line.includes('error:')) errors.push(line.trim());
    }
    if (errors.length === 0) errors.push(stderr || e.message);
    return { success: false, errors };
  }

  // Find artifacts
  const files = fs.readdirSync(output);
  const wasmFile = files.find(f => f.endsWith('.wasm'));
  if (!wasmFile) {
    return { success: false, errors: ['No .wasm output produced'] };
  }

  const wasmPath = path.join(output, wasmFile);
  const contractName = path.basename(wasmFile, '.wasm');
  const wasmSize = fs.statSync(wasmPath).size;

  const contractFile = files.find(f => f.endsWith('.contract'));
  const abiPath = contractFile ? path.join(output, contractFile) : undefined;

  return { success: true, wasmPath, abiPath, contractName, wasmSize };
}

/**
 * Load WASM bytes from compiled artifact.
 */
function loadWasm(wasmPath) {
  return fs.readFileSync(wasmPath);
}

/**
 * Load ABI from .contract file (Polkadot metadata format).
 */
function loadABI(abiPath) {
  if (!abiPath || !fs.existsSync(abiPath)) return null;
  try {
    return JSON.parse(fs.readFileSync(abiPath, 'utf-8'));
  } catch {
    return null;
  }
}

module.exports = { findSolang, getSolangVersion, compile, loadWasm, loadABI };
