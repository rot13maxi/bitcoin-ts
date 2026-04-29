/**
 * Bitcoin Core Transaction Index
 * Ported from src/index/txindex.h/cpp
 * 
 * Provides indexing of transactions by hash for efficient lookup
 * 
 * @module txindex
 */

import { CTransaction, CTxOut } from '../primitives';

/**
 * Transaction index entry
 */
export interface TxIndexEntry {
    /** The transaction hash */
    tx_hash: Uint8Array;
    /** The block hash containing this transaction */
    block_hash: Uint8Array;
    /** File position of the transaction */
    file_num: number;
    /** Byte offset within the file */
    data_pos: number;
    /** Size of the serialized transaction */
    tx_size: number;
}

/**
 * Find transaction result
 */
export interface FindTxResult {
    /** Whether the transaction was found */
    found: boolean;
    /** Block hash containing the transaction */
    block_hash?: Uint8Array;
    /** The transaction itself */
    tx?: CTransaction;
}

/**
 * TxIndex provides lookups of transactions by hash
 * 
 * The index is stored in a LevelDB-style database and records
 * the location of each transaction by hash.
 */
export class TxIndex {
    private m_db: Map<string, TxIndexEntry>;
    private m_chain: unknown;
    
    /**
     * Construct the transaction index
     */
    constructor(chain: unknown = null) {
        this.m_chain = chain;
        this.m_db = new Map();
    }
    
    /**
     * Find a transaction by hash
     */
    findTx(txHash: Uint8Array): FindTxResult {
        const key = this.hashToString(txHash);
        const entry = this.m_db.get(key);
        
        if (entry) {
            return {
                found: true,
                block_hash: entry.block_hash,
            };
        }
        
        return { found: false };
    }
    
    /**
     * Get transaction by hash
     */
    getTx(txHash: Uint8Array): CTransaction | null {
        const result = this.findTx(txHash);
        // Would load transaction from disk if found
        return result.tx ?? null;
    }
    
    /**
     * Add a transaction to the index
     */
    addTx(txHash: Uint8Array, blockHash: Uint8Array, fileNum: number, dataPos: number, txSize: number): void {
        const entry: TxIndexEntry = {
            tx_hash: txHash,
            block_hash: blockHash,
            file_num: fileNum,
            data_pos: dataPos,
            tx_size: txSize,
        };
        
        const key = this.hashToString(txHash);
        this.m_db.set(key, entry);
    }
    
    /**
     * Remove a transaction from the index
     */
    removeTx(txHash: Uint8Array): boolean {
        const key = this.hashToString(txHash);
        return this.m_db.delete(key);
    }
    
    /**
     * Get database size (number of indexed transactions)
     */
    size(): number {
        return this.m_db.size;
    }
    
    /**
     * Sync to disk
     */
    sync(): void {
        // Would write to LevelDB
    }
    
    /**
     * Convert hash to string key
     */
    private hashToString(hash: Uint8Array): string {
        return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
    }
}

/**
 * Global transaction index instance
 */
export let g_txindex: TxIndex | null = null;

/**
 * Initialize the global transaction index
 */
export function initTxIndex(chain: unknown = null): TxIndex {
    g_txindex = new TxIndex(chain);
    return g_txindex;
}

/**
 * Get the global transaction index
 */
export function getTxIndex(): TxIndex | null {
    return g_txindex;
}

/**
 * Default transaction index setting (disabled by default in Bitcoin Core)
 */
export const DEFAULT_TXINDEX = false;

/**
 * Lookup a transaction in the global index
 */
export function lookupTx(txHash: Uint8Array): FindTxResult {
    if (g_txindex) {
        return g_txindex.findTx(txHash);
    }
    return { found: false };
}

/**
 * Get transaction from the global index
 */
export function getTx(txHash: Uint8Array): CTransaction | null {
    if (g_txindex) {
        return g_txindex.getTx(txHash);
    }
    return null;
}
