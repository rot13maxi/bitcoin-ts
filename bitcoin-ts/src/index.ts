/**
 * Bitcoin TypeScript Library
 * 
 * A TypeScript port of Bitcoin Core cryptographic primitives and modules.
 * 
 * @package bitcoin-ts
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
// Re-export netaddress (network address types: Network, CNetAddr, CSubNet, CService)
export * from './netaddress';

// Re-export protocol (P2P protocol types: NetMsgType, ServiceFlags, CAddress, CInv)
export * from './protocol';

// Re-export addrman (address manager: AddrMan, AddressPosition, AddrInfo)
export * from './addrman';

// Re-export banman (ban management: BanMan, CBanEntry, banmap_t)
export * from './banman';

// Re-export net (P2P networking constants and types)
export * from './net';

// Re-export validation (block/tx validation: CBlockIndex, MempoolAcceptResult)
export * from './validation';
