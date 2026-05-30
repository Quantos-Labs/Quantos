/**
 * QuantosNodeClient — RPC client to fetch L0 proofs & checkpoints from Quantos.
 */

import axios, { AxiosInstance } from 'axios';
import { QuantosNodeConfig } from '../types/config';
import { L0FinalityProof } from '../types/proof';

export interface RpcRequest {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params: unknown[];
}

export interface RpcResponse<T> {
  jsonrpc: string;
  id: number;
  result?: T;
  error?: { code: number; message: string };
}

export class QuantosNodeClient {
  private http: AxiosInstance;
  private nextId = 1;

  constructor(private config: QuantosNodeConfig) {
    this.http = axios.create({
      baseURL: config.rpcUrl,
      timeout: config.timeoutMs ?? 30000,
      headers: config.apiKey ? { 'X-API-Key': config.apiKey } : {},
    });
  }

  private async call<T>(method: string, params: unknown[]): Promise<T> {
    const req: RpcRequest = {
      jsonrpc: '2.0',
      id: this.nextId++,
      method,
      params,
    };
    const { data } = await this.http.post<RpcResponse<T>>('/', req);
    if (data.error) {
      throw new Error(`Quantos RPC error ${data.error.code}: ${data.error.message}`);
    }
    if (data.result === undefined) {
      throw new Error('Quantos RPC returned undefined result');
    }
    return data.result;
  }

  /** Fetch the latest finalized slot number */
  async getFinalizedSlot(): Promise<number> {
    const result = await this.call<string>('qnt_getFinalizedSlot', []);
    return parseInt(result, 10);
  }

  /** Fetch the current slot number */
  async getSlot(): Promise<number> {
    const result = await this.call<string>('qnt_getSlot', []);
    return parseInt(result, 10);
  }

  /**
   * Fetch an L0 finality proof by its checkpoint hash.
   * Returns null if the proof has not yet been generated.
   */
  async getProofByHash(checkpointHash: string): Promise<L0FinalityProof | null> {
    try {
      const result = await this.call<L0FinalityProof>('qnt_getL0Proof', [checkpointHash]);
      return result;
    } catch (e: any) {
      if (e.message?.includes('not found') || e.message?.includes('unknown')) {
        return null;
      }
      throw e;
    }
  }

  /**
   * Fetch the latest L0 finality proof available on the node.
   */
  async getLatestProof(): Promise<L0FinalityProof | null> {
    try {
      const result = await this.call<L0FinalityProof>('qnt_getLatestL0Proof', []);
      return result;
    } catch (e: any) {
      if (e.message?.includes('not found')) return null;
      throw e;
    }
  }

  /**
   * Submit an external checkpoint (used by off-chain services / bridges).
   */
  async submitExternalCheckpoint(
    checkpoint: unknown,
    signature: string
  ): Promise<string> {
    return this.call<string>('qnt_submitExternalCheckpoint', [checkpoint, signature]);
  }
}
