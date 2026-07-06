/**
 * Quantos JSON-RPC Client
 */

const http = require('http');
const https = require('https');
const url = require('url');

/**
 * Send a JSON-RPC request to a Quantos node.
 */
async function rpcCall(rpcUrl, method, params = []) {
  const parsed = new url.URL(rpcUrl);
  const transport = parsed.protocol === 'https:' ? https : http;

  const body = JSON.stringify({
    jsonrpc: '2.0',
    method,
    params,
    id: Date.now(),
  });

  return new Promise((resolve, reject) => {
    const req = transport.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) reject(new Error(json.error.message || JSON.stringify(json.error)));
          else resolve(json.result);
        } catch (e) {
          reject(new Error(`Invalid JSON response: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('RPC timeout')); });
    req.write(body);
    req.end();
  });
}

/**
 * Deploy a WASM contract.
 */
async function deploy(rpcUrl, wasmHex, deployer, constructorData) {
  const params = {
    bytecode: wasmHex.startsWith('0x') ? wasmHex : `0x${wasmHex}`,
    deployer,
  };
  if (constructorData) params.constructor_data = constructorData;
  return rpcCall(rpcUrl, 'qnt_deployContract', [params]);
}

/**
 * Call a deployed contract.
 */
async function call(rpcUrl, contractAddress, caller, inputData) {
  return rpcCall(rpcUrl, 'qnt_callContract', [{
    contract_address: contractAddress,
    caller,
    input_data: inputData,
  }]);
}

/**
 * Send a state-changing transaction to a deployed contract.
 */
async function sendTx(rpcUrl, contractAddress, caller, inputData) {
  return rpcCall(rpcUrl, 'qnt_sendTransaction', [{
    contract_address: contractAddress,
    caller,
    input_data: inputData,
  }]);
}

/**
 * Get account balance.
 */
async function getBalance(rpcUrl, address) {
  return rpcCall(rpcUrl, 'qnt_getBalance', [address]);
}

/**
 * Get node info.
 */
async function getNodeInfo(rpcUrl) {
  return rpcCall(rpcUrl, 'qnt_nodeInfo', []);
}

module.exports = { rpcCall, deploy, call, sendTx, getBalance, getNodeInfo };
