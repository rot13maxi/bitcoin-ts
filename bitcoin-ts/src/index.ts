/**
 * Bitcoin TypeScript Library
 *
 * A TypeScript port of Bitcoin Core cryptographic primitives and modules.
 */

// Re-export crypto module
export * from './crypto';

// Re-export script module
export * from './script';

// Re-export consensus module
export * from './consensus';

// Re-export primitives
export * from './primitives';

// Re-export coins (UTXO management)
export * from './coins';

// Re-export memusage (memory tracking)
export * from './memusage';

// Re-export txrequest (transaction request tracker)
export * from './txrequest';

// Re-export txmempool
export * from './txmempool';

// Re-export Layer 5: Validation/Network
export * from './netaddress';
export * from './protocol';
export * from './addrman';
export * from './banman';
export * from './net';
export * from './validation';

// Re-export Layer 6: Wallet/RPC/Index (PSBT types override primitives types)
export type {
    PSBTInput,
    PSBTOutput,
    PartiallySignedTransaction,
} from './psbt';

export {
    PSBT_MAGIC_BYTES,
    PSBT_SEPARATOR,
    PSBTError,
    PSBTRole,
    createPSBT,
    psbtInputSigned,
    countPSBTUnsignedInputs,
} from './psbt';

// Export rest of psbt
export * from './psbt';

// Re-export blockfilter
export type * from './blockfilter';

// Re-export txindex
export * from './txindex';

// Re-export external_signer
export * from './external_signer';
