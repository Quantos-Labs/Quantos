#!/usr/bin/env node

/**
 * Quantos CLI
 * 
 * Usage:
 *   quantos compile <file.sol> [--output <dir>]
 *   quantos deploy <file.wasm> --from <address> [--rpc <url>] [--args <type:value,...>] [--selector <hex>]
 *   quantos call <contract> <function(args)> [--args <type:value,...>] [--from <addr>] [--rpc <url>]
 *   quantos send <contract> <function(args)> [--args <type:value,...>] [--from <addr>] [--rpc <url>]
 *   quantos info [--rpc <url>]
 *   quantos encode <type> <value>
 *   quantos decode <hex> [--type <type>]
 *   quantos selector <signature>
 */

const { program } = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const path = require('path');
const fs = require('fs');

const { compile, loadWasm, loadABI, findSolang, getSolangVersion } = require('../src/compiler');
const { computeSelector, encodeArg, buildCalldata, decodeReturnData, encodeUint256LE } = require('../src/encoding');
const { deploy, call, sendTx, getNodeInfo } = require('../src/rpc');

const DEFAULT_RPC = process.env.QUANTOS_RPC || 'http://127.0.0.1:8545';

program
  .name('quantos')
  .description('Quantos CLI — Solidity smart contracts on QuantosVM')
  .version('1.0.0');

// ── compile ──
program
  .command('compile <solFile>')
  .description('Compile Solidity to WASM via Solang (Polkadot target)')
  .option('-o, --output <dir>', 'Output directory', './build')
  .action((solFile, opts) => {
    const spinner = ora('Compiling...').start();
    const result = compile(solFile, opts.output);
    if (result.success) {
      spinner.succeed(chalk.green(`Compiled ${chalk.bold(result.contractName)}`));
      console.log(`  WASM: ${chalk.cyan(result.wasmPath)} (${(result.wasmSize / 1024).toFixed(1)} KB)`);
      if (result.abiPath) console.log(`  ABI:  ${chalk.cyan(result.abiPath)}`);
    } else {
      spinner.fail(chalk.red('Compilation failed'));
      result.errors.forEach(e => console.error(chalk.red(`  ${e}`)));
      process.exit(1);
    }
  });

// ── deploy ──
program
  .command('deploy <wasmFile>')
  .description('Deploy a compiled WASM contract to Quantos')
  .requiredOption('--from <address>', 'Deployer address (QTS:... or hex)')
  .option('--rpc <url>', 'RPC endpoint', DEFAULT_RPC)
  .option('--args <args>', 'Constructor args: type:value,type:value (e.g. uint256:1000000)')
  .option('--selector <hex>', 'Constructor selector (4 bytes hex)')
  .option('--abi <path>', 'Path to .contract ABI file')
  .action(async (wasmFile, opts) => {
    const spinner = ora('Deploying...').start();
    try {
      const wasmBytes = fs.readFileSync(path.resolve(wasmFile));
      const wasmHex = wasmBytes.toString('hex');

      let ctorCalldata;
      if (opts.args || opts.selector) {
        const selectorHex = opts.selector || '00000000';
        const args = opts.args ? opts.args.split(',').map(a => {
          const [type, ...rest] = a.split(':');
          return { type, value: rest.join(':') };
        }) : [];

        // Try to get selector from ABI if not provided
        let finalSelector = selectorHex;
        if (!opts.selector && opts.abi) {
          const abi = loadABI(opts.abi);
          if (abi?.spec?.constructors?.[0]?.selector) {
            finalSelector = abi.spec.constructors[0].selector.replace(/^0x/, '');
          }
        }
        ctorCalldata = buildCalldata(finalSelector, args);
      }

      const result = await deploy(opts.rpc, wasmHex, opts.from, ctorCalldata);
      const addr = result?.address || result;
      spinner.succeed(chalk.green(`Deployed at ${chalk.bold(addr)}`));
      if (result?.tx_hash) console.log(`  Tx: ${chalk.gray(result.tx_hash)}`);
    } catch (e) {
      spinner.fail(chalk.red(`Deploy failed: ${e.message}`));
      process.exit(1);
    }
  });

// ── call (read-only) ──
program
  .command('call <contract> <signature>')
  .description('Call a read-only function on a deployed contract')
  .option('--args <args>', 'Function args: type:value,type:value')
  .option('--from <address>', 'Caller address', 'QTS:' + '00'.repeat(32))
  .option('--rpc <url>', 'RPC endpoint', DEFAULT_RPC)
  .option('--type <type>', 'Return type for decoding (uint256, address, bool)')
  .action(async (contract, signature, opts) => {
    try {
      const selector = computeSelector(signature);
      const args = opts.args ? opts.args.split(',').map(a => {
        const [type, ...rest] = a.split(':');
        return { type, value: rest.join(':') };
      }) : [];
      const calldata = buildCalldata(selector, args);

      const result = await call(opts.rpc, contract, opts.from, calldata);
      const returnHex = result?.return_data || result;
      if (returnHex) {
        const decoded = decodeReturnData(returnHex, opts.type);
        console.log(chalk.green(`${signature} => ${chalk.bold(decoded)}`));
        console.log(chalk.gray(`  raw: ${returnHex}`));
      } else {
        console.log(chalk.green(`${signature} => ${JSON.stringify(result)}`));
      }
    } catch (e) {
      console.error(chalk.red(`Call failed: ${e.message}`));
      process.exit(1);
    }
  });

// ── send (state-changing tx) ──
program
  .command('send <contract> <signature>')
  .description('Send a state-changing transaction to a contract')
  .option('--args <args>', 'Function args: type:value,type:value')
  .requiredOption('--from <address>', 'Sender address')
  .option('--rpc <url>', 'RPC endpoint', DEFAULT_RPC)
  .action(async (contract, signature, opts) => {
    const spinner = ora(`Sending ${signature}...`).start();
    try {
      const selector = computeSelector(signature);
      const args = opts.args ? opts.args.split(',').map(a => {
        const [type, ...rest] = a.split(':');
        return { type, value: rest.join(':') };
      }) : [];
      const calldata = buildCalldata(selector, args);

      const result = await sendTx(opts.rpc, contract, opts.from, calldata);
      spinner.succeed(chalk.green(`${signature} sent`));
      console.log(`  Result: ${JSON.stringify(result)}`);
    } catch (e) {
      spinner.fail(chalk.red(`Send failed: ${e.message}`));
      process.exit(1);
    }
  });

// ── info ──
program
  .command('info')
  .description('Get Quantos node info and Solang version')
  .option('--rpc <url>', 'RPC endpoint', DEFAULT_RPC)
  .action(async (opts) => {
    console.log(chalk.bold('Quantos CLI v1.0.0\n'));

    // Solang
    const solang = findSolang();
    if (solang) {
      console.log(`  Solang:   ${chalk.green(getSolangVersion(solang))}`);
      console.log(`  Path:     ${chalk.gray(solang)}`);
    } else {
      console.log(`  Solang:   ${chalk.red('not found')} — install: cargo install solang`);
    }

    // Node
    try {
      const info = await getNodeInfo(opts.rpc);
      console.log(`  Node:     ${chalk.green('connected')} (${opts.rpc})`);
      if (info) console.log(`  Info:     ${JSON.stringify(info)}`);
    } catch {
      console.log(`  Node:     ${chalk.yellow('offline')} (${opts.rpc})`);
    }

    console.log(`\n  Encoding: ${chalk.cyan('Little-Endian uint256')} (Solang/Polkadot)`);
    console.log(`  Addresses: ${chalk.cyan('32 bytes')}`);
  });

// ── encode ──
program
  .command('encode <type> <value>')
  .description('Encode a value to hex (LE for uint256)')
  .action((type, value) => {
    const encoded = encodeArg(type, value);
    const hex = encoded.toString('hex');
    console.log(type.toLowerCase() === 'address' ? 'QTS:' + hex : '0x' + hex);
  });

// ── decode ──
program
  .command('decode <hex>')
  .description('Decode hex return data')
  .option('--type <type>', 'Type hint (uint256, address, bool)')
  .action((hex, opts) => {
    console.log(decodeReturnData(hex, opts.type));
  });

// ── selector ──
program
  .command('selector <signature>')
  .description('Compute Keccak-256 function selector')
  .action((signature) => {
    const sel = computeSelector(signature);
    console.log(`${signature} => 0x${sel}`);
  });

program.parse();
