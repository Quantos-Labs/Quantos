import { L0FinalityProof } from "./types";

export async function fetchProof(
  rpcUrl: string,
  proofHash: string
): Promise<L0FinalityProof> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "qnt_getL0Proof",
      params: [proofHash],
    }),
  });

  if (!response.ok) {
    throw new Error(`RPC returned status ${response.status}`);
  }

  const json = await response.json();
  if (json.error) {
    throw new Error(`RPC error: ${JSON.stringify(json.error)}`);
  }

  const proofHex: string = json.result;
  if (!proofHex) {
    throw new Error("Missing result field in RPC response");
  }

  const proofBytes = hexToBytes(proofHex);
  const proofStr = new TextDecoder().decode(proofBytes);
  return JSON.parse(proofStr) as L0FinalityProof;
}

export async function fetchLatestProof(
  rpcUrl: string
): Promise<L0FinalityProof> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "qnt_getLatestL0Proof",
      params: [],
    }),
  });

  if (!response.ok) {
    throw new Error(`RPC returned status ${response.status}`);
  }

  const json = await response.json();
  if (json.error) {
    throw new Error(`RPC error: ${JSON.stringify(json.error)}`);
  }

  const proofHex: string = json.result;
  if (!proofHex) {
    throw new Error("Missing result field in RPC response");
  }

  const proofBytes = hexToBytes(proofHex);
  const proofStr = new TextDecoder().decode(proofBytes);
  return JSON.parse(proofStr) as L0FinalityProof;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}
