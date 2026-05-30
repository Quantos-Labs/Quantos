import axios from 'axios';
import { ExternalCheckpoint, L0ProofResponse } from './types';

export class QuantosL0Client {
  private rpcUrl: string;

  constructor(rpcUrl: string) {
    this.rpcUrl = rpcUrl;
  }

  async submitCheckpoint(checkpoint: ExternalCheckpoint): Promise<L0ProofResponse> {
    try {
      const response = await axios.post(this.rpcUrl, {
        jsonrpc: '2.0',
        id: 1,
        method: 'qnt_submitExternalCheckpoint',
        params: [checkpoint],
      });

      if (response.data.error) {
        throw new Error(`RPC error: ${response.data.error.message}`);
      }

      return response.data.result;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`Failed to submit checkpoint: ${error.message}`);
      }
      throw error;
    }
  }

  async getL0Proof(proofHash: string): Promise<any> {
    try {
      const response = await axios.post(this.rpcUrl, {
        jsonrpc: '2.0',
        id: 1,
        method: 'qnt_getL0Proof',
        params: [proofHash],
      });

      if (response.data.error) {
        throw new Error(`RPC error: ${response.data.error.message}`);
      }

      return response.data.result;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`Failed to get L0 proof: ${error.message}`);
      }
      throw error;
    }
  }

  async getLatestL0Proof(): Promise<any> {
    try {
      const response = await axios.post(this.rpcUrl, {
        jsonrpc: '2.0',
        id: 1,
        method: 'qnt_getLatestL0Proof',
        params: [],
      });

      if (response.data.error) {
        throw new Error(`RPC error: ${response.data.error.message}`);
      }

      return response.data.result;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`Failed to get latest L0 proof: ${error.message}`);
      }
      throw error;
    }
  }

  async getL0Metrics(): Promise<any> {
    try {
      const response = await axios.post(this.rpcUrl, {
        jsonrpc: '2.0',
        id: 1,
        method: 'qnt_getL0Metrics',
        params: [],
      });

      if (response.data.error) {
        throw new Error(`RPC error: ${response.data.error.message}`);
      }

      return response.data.result;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`Failed to get L0 metrics: ${error.message}`);
      }
      throw error;
    }
  }
}
