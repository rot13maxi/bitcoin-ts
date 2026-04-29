// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Network Address Types
 * TypeScript port of Bitcoin Core's src/netaddress.h
 * 
 * Core networking address types: Network enum, CNetAddr, CSubNet, CService.
 * These types represent Bitcoin P2P network addresses across IPv4, IPv6,
 * Tor, I2P, CJDNS, and internal address spaces.
 */

/**
 * A network type (IP address family).
 * 
 * An address may belong to more than one network, e.g. 10.0.0.1 belongs to
 * both NET_UNROUTABLE and NET_IPV4. NET_MAX is the sentinel value.
 */
export enum Network {
    /** Addresses not publicly routable on the global Internet. */
    NET_UNROUTABLE = 0,
    /** IPv4 address. */
    NET_IPV4,
    /** IPv6 address. */
    NET_IPV6,
    /** Tor v2 or v3 address. */
    NET_ONION,
    /** I2P address. */
    NET_I2P,
    /** CJDNS address. */
    NET_CJDNS,
    /** Internal address (hash-based placeholder used in AddrMan). */
    NET_INTERNAL,
    /** Sentinel: number of NET_* constants. */
    NET_MAX,
}

/** BIP155 network ids recognized by the Bitcoin protocol. */
export enum BIP155Network {
    IPV4 = 1,
    IPV6 = 2,
    TORV2 = 3,
    TORV3 = 4,
    I2P = 5,
    CJDNS = 6,
}

// Address size constants
export const ADDR_IPV4_SIZE = 4;
export const ADDR_IPV6_SIZE = 16;
export const ADDR_TORV3_SIZE = 32;
export const ADDR_I2P_SIZE = 32;
export const ADDR_CJDNS_SIZE = 16;
export const ADDR_INTERNAL_SIZE = 10;
export const MAX_ADDRV2_SIZE = 512;

/** Prefix of an IPv6 address embedding an IPv4 address (::FFFF:0:0/96). */
export const IPV4_IN_IPV6_PREFIX = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
]);

/** Prefix of an IPv6 address embedding a Tor v2 address. */
export const TORV2_IN_IPV6_PREFIX = new Uint8Array([0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43]);

/** Prefix of an IPv6 address embedding an internal address (0xFD + SHA256("bitcoin")[0:5]). */
export const INTERNAL_IN_IPV6_PREFIX = new Uint8Array([0xFD, 0x6B, 0x88, 0xC0, 0x87, 0x24]);

/** All CJDNS addresses start with 0xFC. */
export const CJDNS_PREFIX = 0xfc;

/** I2P SAM 3.1 and earlier force port to 0. */
export const I2P_SAM31_PORT = 0;

/**
 * Address encoding format used in serialization.
 */
export enum CNetAddrEncoding {
    V1, /** Pre-BIP155 encoding (legacy) */
    V2, /** BIP155 encoding (supports all address types) */
}

/**
 * CNetAddr — Network address.
 * 
 * Represents an IP address on the Bitcoin P2P network. Supports IPv4, IPv6,
 * Tor, I2P, CJDNS, and internal addresses. Can embed smaller address types
 * in larger representations (e.g. IPv4 in IPv6).
 */
export interface CNetAddr {
    /** Raw address bytes. For IPv4: 16 bytes (with IPv4-in-IPv6 embedding). For IPv6: 16 bytes. */
    m_addr: Uint8Array;
    /** Network type of this address. */
    m_net: Network;
    /** Scope id for scoped/link-local IPv6 addresses (RFC 4007). */
    m_scope_id: number;
}

/**
 * Create a new CNetAddr with default values.
 */
export function newCNetAddr(): CNetAddr {
    return {
        m_addr: new Uint8Array(ADDR_IPV6_SIZE),
        m_net: Network.NET_IPV6,
        m_scope_id: 0,
    };
}

/**
 * Whether this address is an IPv4 address (including IPv4-mapped IPv6).
 */
export function CNetAddr_IsIPv4(addr: CNetAddr): boolean {
    return addr.m_net === Network.NET_IPV4;
}

/**
 * Whether this address is a plain IPv6 address (not mapped IPv4, not Tor).
 */
export function CNetAddr_IsIPv6(addr: CNetAddr): boolean {
    return addr.m_net === Network.NET_IPV6;
}

/**
 * Whether this address is a Tor address.
 */
export function CNetAddr_IsTor(addr: CNetAddr): boolean {
    return addr.m_net === Network.NET_ONION;
}

/**
 * Whether this address is an I2P address.
 */
export function CNetAddr_IsI2P(addr: CNetAddr): boolean {
    return addr.m_net === Network.NET_I2P;
}

/**
 * Whether this address is a CJDNS address.
 */
export function CNetAddr_IsCJDNS(addr: CNetAddr): boolean {
    return addr.m_net === Network.NET_CJDNS;
}

/**
 * Whether this address starts with the CJDNS prefix.
 */
export function CNetAddr_HasCJDNSPrefix(addr: CNetAddr): boolean {
    return addr.m_addr.length > 0 && addr.m_addr[0] === CJDNS_PREFIX;
}

/**
 * Whether this address is a privacy network (Tor or I2P).
 */
export function CNetAddr_IsPrivacyNet(addr: CNetAddr): boolean {
    return CNetAddr_IsTor(addr) || CNetAddr_IsI2P(addr);
}

/**
 * Whether this address is relayable (can be advertised to other peers).
 */
export function CNetAddr_IsRelayable(addr: CNetAddr): boolean {
    return (
        CNetAddr_IsIPv4(addr) ||
        CNetAddr_IsIPv6(addr) ||
        CNetAddr_IsTor(addr) ||
        CNetAddr_IsI2P(addr) ||
        CNetAddr_IsCJDNS(addr)
    );
}

/**
 * Whether this address represents INADDR_ANY (0.0.0.0 or ::).
 */
export function CNetAddr_IsBindAny(addr: CNetAddr): boolean {
    return addr.m_addr.every((b) => b === 0);
}

/**
 * IPv4 private networks (RFC 1918): 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12.
 */
export function CNetAddr_IsRFC1918(addr: CNetAddr): boolean {
    if (!CNetAddr_IsIPv4(addr)) return false;
    // addr.m_addr is IPv4-in-IPv6: bytes 12-15 are the IPv4
    const b = addr.m_addr;
    return (
        b[12] === 10 ||
        (b[12] === 172 && (b[13] & 0xf0) === 0x10) ||
        (b[12] === 192 && b[13] === 168)
    );
}

/**
 * IPv4 ISP-level NAT (RFC 6598): 100.64.0.0/10.
 */
export function CNetAddr_IsRFC6598(addr: CNetAddr): boolean {
    if (!CNetAddr_IsIPv4(addr)) return false;
    const b = addr.m_addr;
    return b[12] === 100 && (b[13] & 0xc0) === 0x40;
}

/**
 * IPv6 unique local address (RFC 4193): FC00::/7.
 */
export function CNetAddr_IsRFC4193(addr: CNetAddr): boolean {
    if (!CNetAddr_IsIPv6(addr)) return false;
    return (addr.m_addr[0] & 0xfe) === 0xfc;
}

/**
 * IPv4 link-local (RFC 3927): 169.254.0.0/16.
 */
export function CNetAddr_IsRFC3927(addr: CNetAddr): boolean {
    if (!CNetAddr_IsIPv4(addr)) return false;
    const b = addr.m_addr;
    return b[12] === 169 && b[13] === 254;
}

/**
 * IPv4 documentation addresses (RFC 5737): 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
 */
export function CNetAddr_IsRFC5737(addr: CNetAddr): boolean {
    if (!CNetAddr_IsIPv4(addr)) return false;
    const b = addr.m_addr;
    return (
        (b[12] === 192 && b[13] === 0 && b[14] === 2) ||
        (b[12] === 198 && b[13] === 51 && b[14] === 100) ||
        (b[12] === 203 && b[13] === 0 && b[14] === 113)
    );
}

/**
 * IPv6 documentation address (RFC 3849): 2001:0DB8::/32.
 */
export function CNetAddr_IsRFC3849(addr: CNetAddr): boolean {
    if (!CNetAddr_IsIPv6(addr)) return false;
    const b = addr.m_addr;
    return (
        b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8
    );
}

/**
 * IPv6 Hurricane Electric (he.net): 2001:0470::/36.
 */
export function CNetAddr_IsHeNet(addr: CNetAddr): boolean {
    if (!CNetAddr_IsIPv6(addr)) return false;
    const b = addr.m_addr;
    return b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x04 && b[3] === 0x70;
}

/**
 * IPv6 Teredo tunneling (RFC 4380): 2001::/32.
 */
export function CNetAddr_IsRFC4380(addr: CNetAddr): boolean {
    if (!CNetAddr_IsIPv6(addr)) return false;
    const b = addr.m_addr;
    return b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00;
}

/**
 * Whether this address is internal (NET_INTERNAL).
 */
export function CNetAddr_IsInternal(addr: CNetAddr): boolean {
    return addr.m_net === Network.NET_INTERNAL;
}

/**
 * Whether this address is routable on the public internet.
 */
export function CNetAddr_IsRoutable(addr: CNetAddr): boolean {
    if (CNetAddr_IsIPv4(addr)) {
        return !(
            CNetAddr_IsRFC1918(addr) ||
            CNetAddr_IsRFC6598(addr) ||
            CNetAddr_IsRFC5737(addr) ||
            CNetAddr_IsLocal(addr) ||
            CNetAddr_IsBindAny(addr)
        );
    }
    if (CNetAddr_IsIPv6(addr)) {
        return !(
            CNetAddr_IsRFC3849(addr) ||
            CNetAddr_IsRFC3927(addr) ||
            CNetAddr_IsRFC4862(addr) ||
            CNetAddr_IsLocal(addr) ||
            CNetAddr_IsBindAny(addr)
        );
    }
    return CNetAddr_IsTor(addr) || CNetAddr_IsI2P(addr) || CNetAddr_IsCJDNS(addr);
}

/**
 * Whether this is a local address (loopback or link-local).
 */
export function CNetAddr_IsLocal(addr: CNetAddr): boolean {
    if (CNetAddr_IsIPv4(addr)) {
        const b = addr.m_addr;
        return b[12] === 127; // 127.0.0.0/8
    }
    if (CNetAddr_IsIPv6(addr)) {
        return addr.m_addr[0] === 0x00 && addr.m_addr[1] === 0x00 &&
            addr.m_addr.every((b, i) => i < 12 || b === 0 || b === 1);
    }
    return false;
}

/**
 * Get the network class of this address.
 */
export function CNetAddr_GetNetClass(addr: CNetAddr): Network {
    if (CNetAddr_IsLocal(addr)) return Network.NET_UNROUTABLE;
    if (CNetAddr_IsRFC1918(addr) || CNetAddr_IsRFC6598(addr)) return Network.NET_UNROUTABLE;
    if (CNetAddr_IsInternal(addr)) return Network.NET_UNROUTABLE;
    if (!CNetAddr_IsRoutable(addr)) return Network.NET_UNROUTABLE;
    return addr.m_net;
}

/**
 * Get the IPv4 address embedded in IPv4-mapped IPv6, SIIT, Teredo, or 6to4 addresses.
 * Returns the IPv4 as a 32-bit unsigned integer, or 0 if none.
 */
export function CNetAddr_GetLinkedIPv4(addr: CNetAddr): number {
    if (!CNetAddr_IsIPv4(addr)) return 0;
    const b = addr.m_addr;
    return (b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15];
}

/**
 * Whether this address has a linked IPv4 address.
 */
export function CNetAddr_HasLinkedIPv4(addr: CNetAddr): boolean {
    return CNetAddr_IsIPv4(addr) && !CNetAddr_IsLocal(addr);
}

/**
 * Get address bytes (the raw m_addr field).
 */
export function CNetAddr_GetAddrBytes(addr: CNetAddr): Uint8Array {
    return addr.m_addr;
}

/**
 * Get the BIP155 network id for this address.
 */
export function CNetAddr_GetBIP155Network(addr: CNetAddr): BIP155Network {
    switch (addr.m_net) {
        case Network.NET_IPV4: return BIP155Network.IPV4;
        case Network.NET_IPV6: return BIP155Network.IPV6;
        case Network.NET_ONION:
            // Check if it's Tor v3 (32 bytes) or v2 (10 bytes embedded in IPv6)
            if (addr.m_addr.length === ADDR_TORV3_SIZE) return BIP155Network.TORV3;
            return BIP155Network.TORV2;
        case Network.NET_I2P: return BIP155Network.I2P;
        case Network.NET_CJDNS: return BIP155Network.CJDNS;
        default: return BIP155Network.IPV6;
    }
}

/**
 * Calculate reachability score between two addresses.
 * Higher values indicate better reachability (lower latency).
 */
/**
 * IPv6 RFC4862 (link-local autoconfig): FE80::/64.
 */
export function CNetAddr_IsRFC4862(addr: CNetAddr): boolean {
    if (!CNetAddr_IsIPv6(addr)) return false;
    const b = addr.m_addr;
    return b[0] === 0xfe && b[1] === 0x80 && b[2] === 0x00 && b[3] === 0x00 && b[4] === 0x00 && b[5] === 0x00 && b[6] === 0x00 && b[7] === 0x00;
}

export function CNetAddr_GetReachabilityFrom(self: CNetAddr, peer: CNetAddr): number {
    const selfRoutable = CNetAddr_IsRoutable(self) && !CNetAddr_IsLocal(self);
    const peerRoutable = CNetAddr_IsRoutable(peer) && !CNetAddr_IsLocal(peer);

    if (selfRoutable && peerRoutable) return 2;
    if (selfRoutable && !peerRoutable) return 3;
    if (!selfRoutable && peerRoutable) return 1;
    return 0;
}

/**
 * Create a CNetAddr from an IPv4 address (4 bytes).
 */
export function newCNetAddrFromIPv4(ipv4Bytes: Uint8Array): CNetAddr {
    if (ipv4Bytes.length !== 4) throw new Error("Invalid IPv4 address length");
    const addr = newCNetAddr();
    addr.m_addr = new Uint8Array(ADDR_IPV6_SIZE);
    addr.m_addr.set(IPV4_IN_IPV6_PREFIX);
    addr.m_addr.set(ipv4Bytes, 12);
    addr.m_net = Network.NET_IPV4;
    return addr;
}

/**
 * Create a CNetAddr from an IPv6 address (16 bytes).
 */
export function newCNetAddrFromIPv6(ipv6Bytes: Uint8Array): CNetAddr {
    if (ipv6Bytes.length !== 16) throw new Error("Invalid IPv6 address length");
    const addr = newCNetAddr();
    addr.m_addr = ipv6Bytes.slice();
    addr.m_net = Network.NET_IPV6;
    return addr;
}

/**
 * Serialize a CNetAddr to V1 format (pre-BIP155, 16 bytes).
 * Returns the serialized bytes, with IPv4 and internal addresses embedded in IPv6.
 */
export function CNetAddr_SerializeV1(addr: CNetAddr): Uint8Array {
    switch (addr.m_net) {
        case Network.NET_IPV6:
            return addr.m_addr.slice();
        case Network.NET_IPV4: {
            const result = new Uint8Array(ADDR_IPV6_SIZE);
            result.set(IPV4_IN_IPV6_PREFIX);
            result.set(addr.m_addr, 12);
            return result;
        }
        case Network.NET_INTERNAL: {
            const result = new Uint8Array(ADDR_IPV6_SIZE);
            result.set(INTERNAL_IN_IPV6_PREFIX);
            result.set(addr.m_addr);
            return result;
        }
        case Network.NET_ONION:
        case Network.NET_I2P:
        case Network.NET_CJDNS:
            return new Uint8Array(ADDR_IPV6_SIZE);
        default:
            return new Uint8Array(ADDR_IPV6_SIZE);
    }
}

/**
 * Deserialize a CNetAddr from V1 format (pre-BIP155, 16 bytes).
 */
export function CNetAddr_DeserializeV1(data: Uint8Array): CNetAddr {
    if (data.length !== ADDR_IPV6_SIZE) throw new Error("Invalid V1 address length");
    const addr = newCNetAddr();
    addr.m_addr = data.slice();

    // Check for IPv4 embedded in IPv6
    let isIPv4 = true;
    for (let i = 0; i < IPV4_IN_IPV6_PREFIX.length; i++) {
        if (data[i] !== IPV4_IN_IPV6_PREFIX[i]) {
            isIPv4 = false;
            break;
        }
    }
    if (isIPv4) {
        addr.m_net = Network.NET_IPV4;
        const ipv4Bytes = data.slice(12, 16);
        addr.m_addr = ipv4Bytes;
        return addr;
    }

    // Check for Tor v2 embedded in IPv6
    let isTorV2 = true;
    for (let i = 0; i < TORV2_IN_IPV6_PREFIX.length; i++) {
        if (data[i] !== TORV2_IN_IPV6_PREFIX[i]) {
            isTorV2 = false;
            break;
        }
    }
    if (isTorV2) {
        addr.m_net = Network.NET_ONION;
        return addr;
    }

    // Check for internal embedded in IPv6
    let isInternal = true;
    for (let i = 0; i < INTERNAL_IN_IPV6_PREFIX.length; i++) {
        if (data[i] !== INTERNAL_IN_IPV6_PREFIX[i]) {
            isInternal = false;
            break;
        }
    }
    if (isInternal) {
        addr.m_net = Network.NET_INTERNAL;
        addr.m_addr = data.slice(INTERNAL_IN_IPV6_PREFIX.length);
        return addr;
    }

    addr.m_net = Network.NET_IPV6;
    return addr;
}

// CSubNet represents a subnet (network + netmask)
export interface CSubNet {
    network: CNetAddr;
    netmask: Uint8Array;
    valid: boolean;
}

/**
 * Create a subnet from a single address (single-host subnet).
 */
export function newCSubNet(addr: CNetAddr): CSubNet {
    return {
        network: addr,
        netmask: new Uint8Array(16),
        valid: addr.m_net === Network.NET_IPV4 || addr.m_net === Network.NET_IPV6,
    };
}

/**
 * Create a subnet from an address and CIDR mask.
 * For IPv4, mask must be 0-32. For IPv6, mask must be 0-128.
 */
export function newCSubNetWithMask(addr: CNetAddr, maskBits: number): CSubNet {
    const subnet: CSubNet = {
        network: addr,
        netmask: new Uint8Array(16),
        valid: false,
    };

    if (addr.m_net === Network.NET_IPV4) {
        if (maskBits < 0 || maskBits > 32) return subnet;
        const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
        const b = subnet.netmask;
        b[0] = (mask >> 24) & 0xff;
        b[1] = (mask >> 16) & 0xff;
        b[2] = (mask >> 8) & 0xff;
        b[3] = mask & 0xff;
        // Zero out remaining for 16-byte storage
        for (let i = 4; i < 16; i++) b[i] = 0;
        subnet.valid = true;
    } else if (addr.m_net === Network.NET_IPV6) {
        if (maskBits < 0 || maskBits > 128) return subnet;
        for (let i = 0; i < 16; i++) {
            if (maskBits >= 8) {
                subnet.netmask[i] = 0xff;
                maskBits -= 8;
            } else if (maskBits > 0) {
                subnet.netmask[i] = (~0 << (8 - maskBits)) & 0xff;
                maskBits = 0;
            }
        }
        subnet.valid = true;
    }
    return subnet;
}

/**
 * Check if an address matches this subnet.
 */
export function CSubNet_Match(subnet: CSubNet, addr: CNetAddr): boolean {
    if (!subnet.valid || subnet.network.m_net !== addr.m_net) return false;

    for (let i = 0; i < subnet.network.m_addr.length; i++) {
        if ((addr.m_addr[i] & subnet.netmask[i]) !== (subnet.network.m_addr[i] & subnet.netmask[i])) {
            return false;
        }
    }
    return true;
}

/**
 * CService — A network address + port.
 * Extends CNetAddr with a port field.
 */
export interface CService extends CNetAddr {
    port: number;
}

/**
 * Create a new CService.
 */
export function newCService(addr: CNetAddr, port: number): CService {
    return {
        ...addr,
        m_addr: addr.m_addr.slice(),
        port: port & 0xffff,
    };
}

/**
 * Get port from a CService.
 */
export function CService_GetPort(svc: CService): number {
    return svc.port;
}

/**
 * Compare two CNetAddr objects for equality.
 */
export function CNetAddr_Equal(a: CNetAddr, b: CNetAddr): boolean {
    if (a.m_net !== b.m_net) return false;
    if (a.m_scope_id !== b.m_scope_id) return false;
    if (a.m_addr.length !== b.m_addr.length) return false;
    for (let i = 0; i < a.m_addr.length; i++) {
        if (a.m_addr[i] !== b.m_addr[i]) return false;
    }
    return true;
}

/**
 * Compare two CNetAddr objects (for use in sorted containers).
 */
export function CNetAddr_LessThan(a: CNetAddr, b: CNetAddr): boolean {
    if (a.m_net !== b.m_net) return a.m_net < b.m_net;
    if (a.m_scope_id !== b.m_scope_id) return a.m_scope_id < b.m_scope_id;
    // Compare address bytes (smaller array first)
    const len = Math.min(a.m_addr.length, b.m_addr.length);
    for (let i = 0; i < len; i++) {
        if (a.m_addr[i] !== b.m_addr[i]) return a.m_addr[i] < b.m_addr[i];
    }
    return a.m_addr.length < b.m_addr.length;
}

/**
 * Compare two CService objects for equality.
 */
export function CService_Equal(a: CService, b: CService): boolean {
    return CNetAddr_Equal(a, b) && a.port === b.port;
}

/**
 * Compare two CService objects (for use in sorted containers).
 */
export function CService_LessThan(a: CService, b: CService): boolean {
    if (!CNetAddr_Equal(a, b)) return CNetAddr_LessThan(a, b);
    return a.port < b.port;
}

/**
 * Compare two CSubNet objects for equality.
 */
export function CSubNet_Equal(a: CSubNet, b: CSubNet): boolean {
    if (a.valid !== b.valid) return false;
    if (!a.valid) return true;
    if (!CNetAddr_Equal(a.network, b.network)) return false;
    for (let i = 0; i < a.netmask.length; i++) {
        if (a.netmask[i] !== b.netmask[i]) return false;
    }
    return true;
}

/**
 * Convert a CNetAddr to a human-readable string.
 */
export function CNetAddr_ToString(addr: CNetAddr): string {
    switch (addr.m_net) {
        case Network.NET_IPV4:
            return `${addr.m_addr[0]}.${addr.m_addr[1]}.${addr.m_addr[2]}.${addr.m_addr[3]}`;
        case Network.NET_IPV6: {
            const groups: string[] = [];
            for (let i = 0; i < 16; i += 2) {
                const val = (addr.m_addr[i] << 8) | addr.m_addr[i + 1];
                groups.push(val.toString(16));
            }
            return groups.join(":");
        }
        case Network.NET_ONION:
            return `[onion address, ${addr.m_addr.length} bytes]`;
        case Network.NET_I2P:
            return `[i2p address, ${addr.m_addr.length} bytes]`;
        case Network.NET_CJDNS:
            return `[cjdns address]`;
        case Network.NET_INTERNAL:
            return `[internal address, ${addr.m_addr.length} bytes]`;
        default:
            return "[unknown]";
    }
}

/**
 * Convert a CService to "host:port" string.
 */
export function CService_ToStringAddrPort(svc: CService): string {
    return `${CNetAddr_ToString(svc)}:${svc.port}`;
}

/**
 * Get the key for a CService (used in AddrMan as the lookup key).
 * Returns the address bytes + port bytes.
 */
export function CService_GetKey(svc: CService): Uint8Array {
    const result = new Uint8Array(svc.m_addr.length + 2);
    result.set(svc.m_addr);
    const portBuf = new Uint8Array(2);
    new DataView(portBuf.buffer).setUint16(0, svc.port, false); // big-endian
    result.set(portBuf, svc.m_addr.length);
    return result;
}
