/**
 * Bitcoin Core External Signer
 * Ported from src/external_signer.h/cpp
 * 
 * Enables interaction with external signing devices/services
 * such as hardware wallets
 * 
 * @module external_signer
 */

import { PartiallySignedTransaction } from '../psbt';

/**
 * External signer interface for hardware wallets
 */
export class ExternalSigner {
    /** The command which handles interaction with the external signer */
    private m_command: string[];
    
    /** Bitcoin mainnet, testnet, etc */
    private m_chain: string;
    
    /** Master key fingerprint */
    public m_fingerprint: string;
    
    /** Device name */
    public m_name: string;
    
    /**
     * Construct an external signer
     * 
     * @param command - Command which handles interaction with the external signer
     * @param chain - "main", "test", "regtest" or "signet"
     * @param fingerprint - Master key fingerprint
     * @param name - Device name
     */
    constructor(
        command: string[],
        chain: string,
        fingerprint: string,
        name: string
    ) {
        this.m_command = command;
        this.m_chain = chain;
        this.m_fingerprint = fingerprint;
        this.m_name = name;
    }
    
    /**
     * Get network argument for the command
     */
    private networkArg(): string[] {
        switch (this.m_chain) {
            case 'main':
                return [];
            case 'test':
                return ['-testnet'];
            case 'regtest':
                return ['-regtest'];
            case 'signet':
                return ['-signet'];
            default:
                return [];
        }
    }
    
    /**
     * Obtain a list of signers
     * Calls `<command> enumerate`
     * 
     * @param command - The command which handles interaction
     * @param chain - "main", "test", "regtest" or "signet"
     * @returns Array of signers
     */
    static async enumerate(
        command: string,
        chain: string
    ): Promise<ExternalSigner[]> {
        // Would spawn the command and parse output
        // Format: `<fingerprint> <name> <master_key_fingerprint>`
        return [];
    }
    
    /**
     * Display address on the device
     * Calls `<command> displayaddress --desc <descriptor>`
     * 
     * @param descriptor - Descriptor specifying which address to display
     * @returns Address information
     */
    async displayAddress(descriptor: string): Promise<ExternalSignerAddress> {
        // Would spawn the command and parse output
        return {
            address: '',
            user_id: 0,
        };
    }
    
    /**
     * Get receive and change descriptors from device
     * Calls `<command> getdescriptors --account <account>`
     * 
     * @param account - BIP32 account (e.g., "m/44'/0'/0'")
     * @returns Object containing descriptor information
     */
    async getDescriptors(account: number): Promise<ExternalSignerDescriptors> {
        // Would spawn the command and parse output
        return {
            receive: [],
            change: [],
        };
    }
    
    /**
     * Sign a Partially Signed Transaction
     * Calls `<command> signtransaction` and passes PSBT via stdin
     * 
     * @param psbt - The PSBT to be signed
     * @returns Error message if failed, empty string if success
     */
    async signTransaction(psbt: PartiallySignedTransaction): Promise<string> {
        // Would spawn the command and communicate via stdin/stdout
        // Would receive signed PSBT on stdout
        return '';
    }
    
    /**
     * Check if this signer matches the given fingerprint
     */
    matchesFingerprint(fingerprint: string): boolean {
        return this.m_fingerprint.toLowerCase() === fingerprint.toLowerCase();
    }
    
    /**
     * Get command as string
     */
    getCommandString(): string {
        return this.m_command.join(' ');
    }
    
    /**
     * Get chain name
     */
    getChain(): string {
        return this.m_chain;
    }
}

/**
 * External signer address information
 */
export interface ExternalSignerAddress {
    /** The Bitcoin address */
    address: string;
    /** User ID (account index) */
    user_id: number;
}

/**
 * External signer descriptor information
 */
export interface ExternalSignerDescriptors {
    /** Receive descriptors for external addresses */
    receive: string[];
    /** Change descriptors for internal addresses */
    change: string[];
}

/**
 * Parse external signer output
 * 
 * Format from external signer:
 * ```
 * {
 *   "signer": <name>,
 *   "fingerprint": <master_key_fingerprint>,
 *   "type": <type>,
 *   ...
 * }
 * ```
 */
export interface ExternalSignerInfo {
    signer: string;
    fingerprint: string;
    type: string;
}

/**
 * Validate a descriptor
 */
export function isValidDescriptor(descriptor: string): boolean {
    // Basic validation - would use actual descriptor parsing
    return descriptor.length > 0 && descriptor.includes('(');
}

/**
 * Descriptor types
 */
export enum DescriptorType {
    P2PKH = 'p2pkh',
    P2SH = 'p2sh',
    P2WPKH = 'wpkh',
    P2WSH = 'wsh',
    P2TR = 'tr',
    MULTISIG = 'multi',
    SCRIPTHASH = 'sh',
    WITNESS_V0 = 'witness_v0',
    TAPROOT = 'taproot',
}

/**
 * Get descriptor script type
 */
export function getDescriptorType(descriptor: string): DescriptorType | null {
    if (descriptor.includes('tr(')) return DescriptorType.TAPROOT;
    if (descriptor.includes('wsh(')) return DescriptorType.P2WSH;
    if (descriptor.includes('wpkh(')) return DescriptorType.P2WPKH;
    if (descriptor.includes('sh(')) return DescriptorType.P2SH;
    if (descriptor.includes('p2pkh')) return DescriptorType.P2PKH;
    if (descriptor.includes('multi(')) return DescriptorType.MULTISIG;
    if (descriptor.includes('combo(')) return DescriptorType.P2PKH; // combo maps to p2pkh
    return null;
}

/**
 * Parse descriptor path
 */
export function parseDescriptorPath(descriptor: string): {
    isBIP44: boolean;
    isBIP49: boolean;
    isBIP84: boolean;
    isBIP86: boolean;
    account: number;
    change: number;
    index: number;
} | null {
    // Extract path from descriptor
    // Format: [.../<change>/<index>]
    const pathMatch = descriptor.match(/\/(\d+)'\/(\d+)\/(\d+)/);
    if (pathMatch) {
        return {
            isBIP44: descriptor.includes('44\'/'),
            isBIP49: descriptor.includes('49\'/'),
            isBIP84: descriptor.includes('84\'/'),
            isBIP86: descriptor.includes('86\'/'),
            account: parseInt(pathMatch[1]),
            change: parseInt(pathMatch[2]),
            index: parseInt(pathMatch[3]),
        };
    }
    return null;
}
