// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin Protocol Types
 * TypeScript port of Bitcoin Core's src/protocol.h
 * 
 * Core P2P protocol types: message header, service flags, CAddress, CInv.
 */

// Protocol version constants (from node/protocol_version.h)
export const PROTOCOL_VERSION = 70016;
export const INIT_PROTO_VERSION = 209;
export const MIN_PEER_PROTO_VERSION = 31800;
export const BIP0031_VERSION = 60000;
export const SENDHEADERS_VERSION = 70012;
export const FEEFILTER_VERSION = 70013;
export const SHORT_IDS_BLOCKS_VERSION = 70014;
export const INVALID_CB_NO_BAN_VERSION = 70015;
export const WTXID_RELAY_VERSION = 70016;

/**
 * Bitcoin P2P message type names.
 */
export namespace NetMsgType {
    export const VERSION = "version";
    export const VERACK = "verack";
    export const ADDR = "addr";
    export const ADDRV2 = "addrv2";
    export const SENDADDRV2 = "sendaddrv2";
    export const INV = "inv";
    export const GETDATA = "getdata";
    export const MERKLEBLOCK = "merkleblock";
    export const GETBLOCKS = "getblocks";
    export const GETHEADERS = "getheaders";
    export const TX = "tx";
    export const HEADERS = "headers";
    export const BLOCK = "block";
    export const GETADDR = "getaddr";
    export const MEMPOOL = "mempool";
    export const PING = "ping";
    export const PONG = "pong";
    export const NOTFOUND = "notfound";
    export const FILTERLOAD = "filterload";
    export const FILTERADD = "filteradd";
    export const FILTERCLEAR = "filterclear";
    export const SENDHEADERS = "sendheaders";
    export const FEEFILTER = "feefilter";
    export const SENDCMPCT = "sendcmpct";
    export const CMPCTBLOCK = "cmpctblock";
    export const GETBLOCKTXN = "getblocktxn";
    export const BLOCKTXN = "blocktxn";
    export const GETCFILTERS = "getcfilters";
    export const CFILTER = "cfilter";
    export const GETCFHEADERS = "getcfheaders";
    export const CFHEADERS = "cfheaders";
    export const GETCFCHECKPT = "getcfcheckpt";
    export const CFCHECKPT = "cfcheckpt";
    export const WTXIDRELAY = "wtxidrelay";
    export const SENDTXRCNCL = "sendtxrcncl";
}

/** All known P2P message types in canonical order. */
export const ALL_NET_MESSAGE_TYPES = [
    NetMsgType.VERSION,
    NetMsgType.VERACK,
    NetMsgType.ADDR,
    NetMsgType.ADDRV2,
    NetMsgType.SENDADDRV2,
    NetMsgType.INV,
    NetMsgType.GETDATA,
    NetMsgType.MERKLEBLOCK,
    NetMsgType.GETBLOCKS,
    NetMsgType.GETHEADERS,
    NetMsgType.TX,
    NetMsgType.HEADERS,
    NetMsgType.BLOCK,
    NetMsgType.GETADDR,
    NetMsgType.MEMPOOL,
    NetMsgType.PING,
    NetMsgType.PONG,
    NetMsgType.NOTFOUND,
    NetMsgType.FILTERLOAD,
    NetMsgType.FILTERADD,
    NetMsgType.FILTERCLEAR,
    NetMsgType.SENDHEADERS,
    NetMsgType.FEEFILTER,
    NetMsgType.SENDCMPCT,
    NetMsgType.CMPCTBLOCK,
    NetMsgType.GETBLOCKTXN,
    NetMsgType.BLOCKTXN,
    NetMsgType.GETCFILTERS,
    NetMsgType.CFILTER,
    NetMsgType.GETCFHEADERS,
    NetMsgType.CFHEADERS,
    NetMsgType.GETCFCHECKPT,
    NetMsgType.CFCHECKPT,
    NetMsgType.WTXIDRELAY,
    NetMsgType.SENDTXRCNCL,
] as const;

/**
 * nServices flags — what services a peer supports.
 * These are bit flags that describe node capabilities.
 */
export enum ServiceFlags {
    /** No services. */
    NODE_NONE = 0,
    /** Node can serve the complete block chain. */
    NODE_NETWORK = 1 << 0,
    /** Node supports BIP37 bloom filters. */
    NODE_BLOOM = 1 << 2,
    /** Node can provide witness data (SegWit). */
    NODE_WITNESS = 1 << 3,
    /** Node supports BIP157/BIP158 compact filters. */
    NODE_COMPACT_FILTERS = 1 << 6,
    /** NODE_NETWORK with limited historical data (last 288 blocks). */
    NODE_NETWORK_LIMITED = 1 << 10,
    /** Node supports BIP324 transport (P2P v2 encryption). */
    NODE_P2P_V2 = 1 << 11,
}

/**
 * Standard service flags for DNS seed nodes.
 */
export const SEEDS_SERVICE_FLAGS = ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS;

/**
 * Whether a peer with given services may have useful address storage.
 */
export function MayHaveUsefulAddressDB(services: ServiceFlags): boolean {
    return !!(services & (ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_NETWORK_LIMITED));
}

/**
 * Serialize a service flags bitmask to human-readable strings.
 */
export function ServiceFlags_ToStrings(flags: ServiceFlags): string[] {
    const result: string[] = [];
    if (flags & ServiceFlags.NODE_NETWORK) result.push("NETWORK");
    if (flags & ServiceFlags.NODE_BLOOM) result.push("BLOOM");
    if (flags & ServiceFlags.NODE_WITNESS) result.push("WITNESS");
    if (flags & ServiceFlags.NODE_COMPACT_FILTERS) result.push("COMPACT_FILTERS");
    if (flags & ServiceFlags.NODE_NETWORK_LIMITED) result.push("NETWORK_LIMITED");
    if (flags & ServiceFlags.NODE_P2P_V2) result.push("P2P_V2");
    const unknown = flags & ~(ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_BLOOM |
        ServiceFlags.NODE_WITNESS | ServiceFlags.NODE_COMPACT_FILTERS |
        ServiceFlags.NODE_NETWORK_LIMITED | ServiceFlags.NODE_P2P_V2);
    if (unknown !== 0) {
        result.push(`UNKNOWN[${unknown}]`);
    }
    return result;
}

/**
 * CMessageHeader — P2P message header format.
 * 
 * Layout (for mainnet message start = f9beb4d9):
 * - 4 bytes: message start (network-specific magic)
 * - 12 bytes: message type (zero-padded ASCII)
 * - 4 bytes: payload size (little-endian uint32)
 * - 4 bytes: checksum (SHA256d of payload, first 4 bytes)
 * 
 * Total: 24 bytes.
 */
export interface CMessageHeader {
    /** Network-specific magic bytes (e.g., 0xf9beb4d9 for mainnet). */
    pchMessageStart: Uint8Array;
    /** Message type (12 bytes, zero-padded ASCII). */
    m_msg_type: Uint8Array;
    /** Payload size in bytes. */
    nMessageSize: number;
    /** Checksum (first 4 bytes of SHA256d of payload). */
    pchChecksum: Uint8Array;
}

export const MESSAGE_TYPE_SIZE = 12;
export const MESSAGE_SIZE_SIZE = 4;
export const CHECKSUM_SIZE = 4;
export const MESSAGE_SIZE_OFFSET = 16; // 4 (start) + 12 (type)
export const CHECKSUM_OFFSET = 20; // MESSAGE_SIZE_OFFSET + 4
export const HEADER_SIZE = 24; // 4 + 12 + 4 + 4

/**
 * Default empty message header.
 */
export function newCMessageHeader(): CMessageHeader {
    return {
        pchMessageStart: new Uint8Array(4),
        m_msg_type: new Uint8Array(MESSAGE_TYPE_SIZE),
        nMessageSize: 0xffffffff >>> 0, // max uint32 as sentinel
        pchChecksum: new Uint8Array(CHECKSUM_SIZE),
    };
}

/**
 * Create a message header from a message type and payload.
 */
export function newCMessageHeaderFromParams(
    messageStart: Uint8Array,
    msgType: string,
    messageSize: number,
    checksum: Uint8Array,
): CMessageHeader {
    const header: CMessageHeader = newCMessageHeader();
    header.pchMessageStart = messageStart.slice();
    header.nMessageSize = messageSize;
    header.pchChecksum = checksum.slice();
    
    // Encode message type as 12-byte zero-padded ASCII
    const msgBytes = new TextEncoder().encode(msgType);
    header.m_msg_type = new Uint8Array(MESSAGE_TYPE_SIZE);
    for (let i = 0; i < Math.min(msgBytes.length, MESSAGE_TYPE_SIZE); i++) {
        header.m_msg_type[i] = msgBytes[i];
    }
    return header;
}

/**
 * Read the message type from a header as a string.
 */
export function CMessageHeader_GetMessageType(header: CMessageHeader): string {
    // Trim trailing null bytes
    let end = MESSAGE_TYPE_SIZE;
    while (end > 0 && header.m_msg_type[end - 1] === 0) end--;
    const bytes = header.m_msg_type.slice(0, end);
    return new TextDecoder().decode(bytes);
}

/**
 * Check if the message type is valid (recognized, zero-padded properly).
 */
export function CMessageHeader_IsMessageTypeValid(header: CMessageHeader): boolean {
    // Must be null-padded after the actual type
    const typeStr = CMessageHeader_GetMessageType(header);
    if (typeStr.length === 0) return false;
    
    // Check all bytes after typeStr are zeros
    const encoded = new TextEncoder().encode(typeStr);
    for (let i = encoded.length; i < MESSAGE_TYPE_SIZE; i++) {
        if (header.m_msg_type[i] !== 0) return false;
    }
    
    // Check it's a known message type
    return ALL_NET_MESSAGE_TYPES.includes(typeStr as typeof ALL_NET_MESSAGE_TYPES[number]);
}

/**
 * Serialize a message header to bytes.
 * Layout: start(4) + type(12) + size(4) + checksum(4) = 24 bytes.
 */
export function CMessageHeader_Serialize(header: CMessageHeader): Uint8Array {
    const result = new Uint8Array(HEADER_SIZE);
    result.set(header.pchMessageStart, 0);
    result.set(header.m_msg_type, 4);
    const sizeView = new DataView(result.buffer);
    sizeView.setUint32(16, header.nMessageSize, true);
    result.set(header.pchChecksum, 20);
    return result;
}

/**
 * Deserialize a message header from bytes.
 */
export function CMessageHeader_Deserialize(data: Uint8Array): CMessageHeader {
    if (data.length < HEADER_SIZE) throw new Error("Message header too short");
    const header = newCMessageHeader();
    header.pchMessageStart = data.slice(0, 4);
    header.m_msg_type = data.slice(4, 16);
    const sizeView = new DataView(data.buffer, data.byteOffset);
    header.nMessageSize = sizeView.getUint32(16, true);
    header.pchChecksum = data.slice(20, 24);
    return header;
}

// CAddress format constants
const DISK_VERSION_INIT = 220000;
const DISK_VERSION_IGNORE_MASK = 0x7ffffff;
const DISK_VERSION_ADDRV2 = 1 << 29;

/**
 * CAddress — A network address with services and timestamp.
 * 
 * Represents a peer's address as advertised in the P2P network.
 * Extends CService with nTime and nServices fields.
 * 
 * Serialized in two formats:
 * - Network: on the wire (V1 = legacy, V2 = BIP155)
 * - Disk: in addrman database (has embedded version field)
 */
export interface CAddress {
    /** Underlying network address (CService). */
    addr: CService;
    /** Timestamp of last known connection to this peer. */
    nTime: number;
    /** Services this peer claims to support. */
    nServices: ServiceFlags;
}

export type CAddressFormat = "V1_NETWORK" | "V2_NETWORK" | "V1_DISK" | "V2_DISK";

/**
 * Create a new CAddress.
 */
export function newCAddress(
    addr: CService,
    nServices: ServiceFlags = ServiceFlags.NODE_NONE,
    nTime?: number,
): CAddress {
    return {
        addr,
        nTime: nTime ?? 100000000, // Default: far past (TIME_INIT)
        nServices,
    };
}

/**
 * Compare two CAddress objects for equality.
 */
export function CAddress_Equal(a: CAddress, b: CAddress): boolean {
    return (
        a.nTime === b.nTime &&
        a.nServices === b.nServices &&
        CService_Equal(a.addr, b.addr)
    );
}

/**
 * Serialize a CAddress to V2 network format (BIP155).
 * Format: time(4) + services(varint) + network(address)
 */
export function CAddress_SerializeV2Network(addr: CAddress): Uint8Array {
    const parts: Uint8Array[] = [];

    // nTime as uint32
    const timeBuf = new Uint8Array(4);
    new DataView(timeBuf.buffer).setUint32(0, addr.nTime, true);
    parts.push(timeBuf);

    // nServices as CompactSize (encode as varint)
    let servicesVal: number = addr.nServices;
    const servicesBytes: number[] = [];
    while (servicesVal > 0x7f) {
        servicesBytes.push((servicesVal & 0x7f) | 0x80);
        servicesVal = (servicesVal >>> 0) >> 7;
    }
    servicesBytes.push(servicesVal);
    parts.push(new Uint8Array(servicesBytes));

    // Network address (V2 format)
    // BIP155: [network_id(1)] + [address_len(varint)] + [address_bytes]
    const netId = CNetAddr_GetBIP155Network(addr.addr);
    const addrBytes = addr.addr.m_addr;

    // Special case: internal addresses are embedded in IPv6
    if (CNetAddr_IsInternal(addr.addr)) {
        const v1Bytes = CNetAddr_SerializeV1(addr.addr);
        parts.push(new Uint8Array([BIP155Network.IPV6]));
        parts.push(new Uint8Array([ADDR_IPV6_SIZE]));
        parts.push(v1Bytes);
    } else {
        parts.push(new Uint8Array([netId]));
        // Address length as CompactSize
        const lenBytes: number[] = [];
        let len = addrBytes.length;
        while (len > 0x7f) {
            lenBytes.push((len & 0x7f) | 0x80);
            len >>= 7;
        }
        lenBytes.push(len);
        parts.push(new Uint8Array(lenBytes));
        parts.push(addrBytes);
    }

    // Concatenate
    const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) {
        result.set(p, offset);
        offset += p.length;
    }
    return result;
}

/**
 * Deserialize a CAddress from V2 network format.
 */
export function CAddress_DeserializeV2Network(data: Uint8Array): CAddress {
    let pos = 0;

    // nTime
    const timeView = new DataView(data.buffer, data.byteOffset);
    const nTime = timeView.getUint32(pos, true);
    pos += 4;

    // nServices (CompactSize)
    let services = 0n;
    let shift = 0;
    while (pos < data.length) {
        const byte = data[pos++];
        services |= BigInt(byte & 0x7f) << BigInt(shift);
        if (!(byte & 0x80)) break;
        shift += 7;
    }
    const nServices = services as unknown as ServiceFlags;

    // Network ID
    const netId = data[pos++];

    // Address bytes
    let addrLen = 0;
    shift = 0;
    while (pos < data.length) {
        const byte = data[pos++];
        addrLen |= (byte & 0x7f) << shift;
        if (!(byte & 0x80)) break;
        shift += 7;
    }

    const addrBytes = data.slice(pos, pos + addrLen);

    // Rebuild CNetAddr from BIP155 network id
    let cnetaddr: CNetAddr;
    switch (netId) {
        case BIP155Network.IPV4:
            cnetaddr = { m_addr: addrBytes.slice(), m_net: Network.NET_IPV4, m_scope_id: 0 };
            break;
        case BIP155Network.IPV6:
            // Check for internal
            let isInternal = true;
            for (let i = 0; i < INTERNAL_IN_IPV6_PREFIX.length; i++) {
                if (addrBytes[i] !== INTERNAL_IN_IPV6_PREFIX[i]) {
                    isInternal = false;
                    break;
                }
            }
            if (isInternal) {
                const internalBytes = addrBytes.slice(INTERNAL_IN_IPV6_PREFIX.length);
                cnetaddr = { m_addr: internalBytes, m_net: Network.NET_INTERNAL, m_scope_id: 0 };
            } else {
                cnetaddr = { m_addr: addrBytes, m_net: Network.NET_IPV6, m_scope_id: 0 };
            }
            break;
        case BIP155Network.TORV2:
            cnetaddr = { m_addr: addrBytes, m_net: Network.NET_ONION, m_scope_id: 0 };
            break;
        case BIP155Network.TORV3:
            cnetaddr = { m_addr: addrBytes, m_net: Network.NET_ONION, m_scope_id: 0 };
            break;
        case BIP155Network.I2P:
            cnetaddr = { m_addr: addrBytes, m_net: Network.NET_I2P, m_scope_id: 0 };
            break;
        case BIP155Network.CJDNS:
            cnetaddr = { m_addr: addrBytes, m_net: Network.NET_CJDNS, m_scope_id: 0 };
            break;
        default:
            cnetaddr = { m_addr: addrBytes, m_net: Network.NET_IPV6, m_scope_id: 0 };
    }

    const svc: CService = { ...cnetaddr, port: 0 };
    return { addr: svc, nTime, nServices };
}

// Re-exports from netaddress for use in this module
import {
    Network,
    BIP155Network,
    CNetAddr,
    CService,
    CSubNet,
    CNetAddr_GetBIP155Network,
    CNetAddr_IsInternal,
    CNetAddr_SerializeV1,
    CService_Equal,
    ADDR_IPV6_SIZE,
    INTERNAL_IN_IPV6_PREFIX,
} from "../netaddress";

export { Network, BIP155Network, CSubNet };

/** getdata message type flags */
export const MSG_WITNESS_FLAG = 1 << 30;
export const MSG_TYPE_MASK = 0xffffffff >>> 2;

/**
 * getdata / inv message types.
 * Used to specify what data object is being requested.
 */
export enum GetDataMsg {
    UNDEFINED = 0,
    MSG_TX = 1,
    MSG_BLOCK = 2,
    MSG_FILTERED_BLOCK = 3,    // BIP37
    MSG_CMPCT_BLOCK = 4,       // BIP152
    MSG_WTX = 5,               // BIP339
    MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG, // BIP144
    MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG,       // BIP144
}

/**
 * CInv — Inventory vector for getdata/inv messages.
 * 
 * Identifies a specific object (transaction or block) by type and hash.
 * The hash is the txid for transactions, block hash for blocks.
 */
export interface CInv {
    type: GetDataMsg;
    hash: Uint8Array; // uint256 (32 bytes)
}

/**
 * Create a new CInv.
 */
export function newCInv(type: GetDataMsg, hash: Uint8Array): CInv {
    return { type, hash: hash.slice() };
}

/**
 * Get the message type string for a CInv.
 */
export function CInv_GetMessageType(inv: CInv): string {
    switch (inv.type) {
        case GetDataMsg.MSG_TX: return NetMsgType.TX;
        case GetDataMsg.MSG_BLOCK: return NetMsgType.BLOCK;
        case GetDataMsg.MSG_FILTERED_BLOCK: return NetMsgType.MERKLEBLOCK;
        case GetDataMsg.MSG_CMPCT_BLOCK: return NetMsgType.CMPCTBLOCK;
        case GetDataMsg.MSG_WTX: return NetMsgType.WTXIDRELAY;
        case GetDataMsg.MSG_WITNESS_BLOCK: return NetMsgType.BLOCK;
        case GetDataMsg.MSG_WITNESS_TX: return NetMsgType.TX;
        default: return "unknown";
    }
}

/**
 * Single-message helper: is this a transaction inventory?
 */
export function CInv_IsMsgTx(inv: CInv): boolean {
    return inv.type === GetDataMsg.MSG_TX;
}

/**
 * Single-message helper: is this a block inventory?
 */
export function CInv_IsMsgBlk(inv: CInv): boolean {
    return inv.type === GetDataMsg.MSG_BLOCK || inv.type === GetDataMsg.MSG_WITNESS_BLOCK;
}

/**
 * Single-message helper: is this a wtxid inventory?
 */
export function CInv_IsMsgWtx(inv: CInv): boolean {
    return inv.type === GetDataMsg.MSG_WTX;
}

/**
 * Single-message helper: is this a filtered block?
 */
export function CInv_IsMsgFilteredBlk(inv: CInv): boolean {
    return inv.type === GetDataMsg.MSG_FILTERED_BLOCK;
}

/**
 * Single-message helper: is this a compact block?
 */
export function CInv_IsMsgCmpctBlk(inv: CInv): boolean {
    return inv.type === GetDataMsg.MSG_CMPCT_BLOCK;
}

/**
 * Single-message helper: is this a witness block?
 */
export function CInv_IsMsgWitnessBlk(inv: CInv): boolean {
    return inv.type === GetDataMsg.MSG_WITNESS_BLOCK;
}

/**
 * Combined helper: is this a transaction (any form)?
 */
export function CInv_IsGenTxMsg(inv: CInv): boolean {
    return (
        inv.type === GetDataMsg.MSG_TX ||
        inv.type === GetDataMsg.MSG_WTX ||
        inv.type === GetDataMsg.MSG_WITNESS_TX
    );
}

/**
 * Combined helper: is this a block (any form)?
 */
export function CInv_IsGenBlkMsg(inv: CInv): boolean {
    return (
        inv.type === GetDataMsg.MSG_BLOCK ||
        inv.type === GetDataMsg.MSG_FILTERED_BLOCK ||
        inv.type === GetDataMsg.MSG_CMPCT_BLOCK ||
        inv.type === GetDataMsg.MSG_WITNESS_BLOCK
    );
}

/**
 * Compare two CInv objects (for sorted containers).
 */
export function CInv_LessThan(a: CInv, b: CInv): boolean {
    if (a.type !== b.type) return a.type < b.type;
    // Compare hash bytes (uint256 comparison)
    for (let i = 0; i < 32; i++) {
        if (a.hash[i] !== b.hash[i]) return a.hash[i] < b.hash[i];
    }
    return false;
}
