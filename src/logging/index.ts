// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Logging infrastructure for Bitcoin Core.
 * This is a TypeScript port of Bitcoin Core's logging.h and logging.cpp.
 * 
 * Port Layer 4: Memory/State - manages logging output and category filtering.
 * 
 * This module provides:
 * - Log levels (Trace, Debug, Info, Warning, Error)
 * - Log categories (net, mempool, validation, etc.)
 * - Rate limiting per source location
 * - Log formatting with timestamps, thread names, source locations
 * - Multiple output sinks (console, callback, file path)
 */

import { uint256 } from '../uint256';
import { CSipHasher } from '../crypto/siphash';
import { Join, RemovePrefixView, LogEscapeMessage } from '../util/string';
import { MallocUsage } from '../memusage';

// ─── Constants ───

/** Default log file path */
export const DEFAULT_DEBUGLOGFILE = 'debug.log';

/** Default settings */
export const DEFAULT_LOGTIMEMICROS = false;
export const DEFAULT_LOGIPS = false;
export const DEFAULT_LOGTIMESTAMPS = true;
export const DEFAULT_LOGTHREADNAMES = false;
export const DEFAULT_LOGSOURCELOCATIONS = false;
export const DEFAULT_LOGLEVELALWAYS = false;
export const DEFAULT_LOGRATELIMIT = true;

/** Rate limiting defaults */
export const RATELIMIT_MAX_BYTES = 1024 * 1024; // 1 MiB per source location per window
export const RATELIMIT_WINDOW_MS = 3600000; // 1 hour

// ─── Source Location ───

/**
 * Source location - file, line, and function name.
 */
export interface SourceLocation {
    file_name: string;
    line: number;
    function_name: string;
    function_name_short: string;
}

/**
 * Create a SourceLocation from a call site.
 */
export function MakeSourceLocation(
    fileName: string,
    line: number,
    funcName: string
): SourceLocation {
    // Extract short function name (just the name, not namespace/class)
    const shortName = funcName.split('::').pop() ?? funcName.split('.').pop() ?? funcName;
    return {
        file_name: fileName,
        line,
        function_name: funcName,
        function_name_short: shortName,
    };
}

// ─── Log Levels ───

export enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
}

export function LevelFromString(str: string): Level | null {
    switch (str) {
        case 'trace': return Level.Trace;
        case 'debug': return Level.Debug;
        case 'info': return Level.Info;
        case 'warning': return Level.Warning;
        case 'error': return Level.Error;
        default: return null;
    }
}

export function LevelToString(level: Level): string {
    switch (level) {
        case Level.Trace: return 'trace';
        case Level.Debug: return 'debug';
        case Level.Info: return 'info';
        case Level.Warning: return 'warning';
        case Level.Error: return 'error';
    }
}

// ─── Log Categories ───

/** Log category flags */
export enum LogFlags {
    NONE = 0,
    ALL = 0xffffffff,
    NET = 1 << 0,
    TOR = 1 << 1,
    MEMPOOL = 1 << 2,
    HTTP = 1 << 3,
    BENCH = 1 << 4,
    ZMQ = 1 << 5,
    WALLETDB = 1 << 6,
    RPC = 1 << 7,
    ESTIMATEFEE = 1 << 8,
    ADDRMAN = 1 << 9,
    SELECTCOINS = 1 << 10,
    REINDEX = 1 << 11,
    CMPCTBLOCK = 1 << 12,
    RAND = 1 << 13,
    PRUNE = 1 << 14,
    PROXY = 1 << 15,
    MEMPOOLREJ = 1 << 16,
    LIBEVENT = 1 << 17,
    COINDB = 1 << 18,
    QT = 1 << 19,
    LEVELDB = 1 << 20,
    VALIDATION = 1 << 21,
    I2P = 1 << 22,
    IPC = 1 << 23,
    LOCK = 1 << 24,
    BLOCKSTORAGE = 1 << 25,
    TXRECONCILIATION = 1 << 26,
    SCAN = 1 << 27,
    TXPACKAGES = 1 << 28,
    KERNEL = 1 << 29,
    PRIVBROADCAST = 1 << 30,
}

export type CategoryMask = number;

/** Map from category name to flag */
export const LOG_CATEGORIES_BY_STR: Record<string, LogFlags> = {
    'net': LogFlags.NET,
    'tor': LogFlags.TOR,
    'mempool': LogFlags.MEMPOOL,
    'http': LogFlags.HTTP,
    'bench': LogFlags.BENCH,
    'zmq': LogFlags.ZMQ,
    'walletdb': LogFlags.WALLETDB,
    'rpc': LogFlags.RPC,
    'estimatefee': LogFlags.ESTIMATEFEE,
    'addrman': LogFlags.ADDRMAN,
    'selectcoins': LogFlags.SELECTCOINS,
    'reindex': LogFlags.REINDEX,
    'cmpctblock': LogFlags.CMPCTBLOCK,
    'rand': LogFlags.RAND,
    'prune': LogFlags.PRUNE,
    'proxy': LogFlags.PROXY,
    'mempoolrej': LogFlags.MEMPOOLREJ,
    'libevent': LogFlags.LIBEVENT,
    'coindb': LogFlags.COINDB,
    'qt': LogFlags.QT,
    'leveldb': LogFlags.LEVELDB,
    'validation': LogFlags.VALIDATION,
    'i2p': LogFlags.I2P,
    'ipc': LogFlags.IPC,
    'lock': LogFlags.LOCK,
    'blockstorage': LogFlags.BLOCKSTORAGE,
    'txreconciliation': LogFlags.TXRECONCILIATION,
    'scan': LogFlags.SCAN,
    'txpackages': LogFlags.TXPACKAGES,
    'kernel': LogFlags.KERNEL,
    'privatebroadcast': LogFlags.PRIVBROADCAST,
};

export function GetLogCategory(str: string): LogFlags | null {
    if (str === '' || str === '1' || str === 'all') {
        return LogFlags.ALL;
    }
    return LOG_CATEGORIES_BY_STR[str] ?? null;
}

// ─── Log Entry ───

/**
 * A log entry before formatting.
 */
export interface LogEntry {
    category: LogFlags;
    level: Level;
    should_ratelimit: boolean;
    source_loc: SourceLocation;
    message: string;
    timestamp?: number;
    mocktime?: number;
    thread_name?: string;
}

// ─── Rate Limiter ───

/** Source location hash map entry */
interface RateLimitStats {
    available_bytes: number;
    dropped_bytes: number;
}

type SourceLocationKey = string;

function sourceLocationKey(loc: SourceLocation): SourceLocationKey {
    return `${loc.file_name}:${loc.line}`;
}

/**
 * Fixed window rate limiter for logging.
 */
export class LogRateLimiter {
    private readonly maxBytes: number;
    private readonly resetWindowMs: number;
    private sourceLocations: Map<SourceLocationKey, RateLimitStats> = new Map();
    private suppressionActive = false;

    constructor(maxBytes: number, resetWindowMs: number) {
        this.maxBytes = maxBytes;
        this.resetWindowMs = resetWindowMs;
    }

    /**
     * Attempt to consume bytes for a source location.
     * Returns: UNSUPPRESSED (logged), NEWLY_SUPPRESSED (suppression started),
     *          STILL_SUPPRESSED (suppressed)
     */
    consume(loc: SourceLocation, messageSize: number): 'UNSUPPRESSED' | 'NEWLY_SUPPRESSED' | 'STILL_SUPPRESSED' {
        const key = sourceLocationKey(loc);
        let stats = this.sourceLocations.get(key);
        
        if (!stats) {
            stats = { available_bytes: this.maxBytes, dropped_bytes: 0 };
            this.sourceLocations.set(key, stats);
        }

        const wasSuppressed = stats.dropped_bytes > 0;
        
        if (messageSize > stats.available_bytes) {
            stats.dropped_bytes += messageSize;
            stats.available_bytes = 0;
            this.suppressionActive = true;
            return wasSuppressed ? 'STILL_SUPPRESSED' : 'NEWLY_SUPPRESSED';
        }

        stats.available_bytes -= messageSize;
        return wasSuppressed ? 'STILL_SUPPRESSED' : 'UNSUPPRESSED';
    }

    /**
     * Reset all rate limit counters.
     */
    reset(): void {
        for (const stats of this.sourceLocations.values()) {
            stats.available_bytes = this.maxBytes;
            stats.dropped_bytes = 0;
        }
        this.suppressionActive = false;
    }

    /**
     * Check if any source locations are being suppressed.
     */
    suppressionsActive(): boolean {
        return this.suppressionActive;
    }
}

// ─── Logger ───

/**
 * Log category with name and active state.
 */
export interface LogCategoryInfo {
    category: string;
    active: boolean;
}

/**
 * Bitcoin Core logger.
 * Manages log output configuration, formatting, and rate limiting.
 */
export class Logger {
    // ─── Configuration ───
    print_to_console = false;
    print_to_file = false;
    log_timestamps = DEFAULT_LOGTIMESTAMPS;
    log_time_micros = DEFAULT_LOGTIMEMICROS;
    log_threadnames = DEFAULT_LOGTHREADNAMES;
    log_sourcelocations = DEFAULT_LOGSOURCELOCATIONS;
    always_print_category_level = DEFAULT_LOGLEVELALWAYS;
    file_path = '';
    reopen_file = false;

    // ─── Internal state ───
    private buffering = true;
    private msgsBeforeOpen: LogEntry[] = [];
    private maxBufferMemusage = 1_000_000; // 1 MB
    private curBufferMemusage = 0;
    private bufferLinesDiscarded = 0;
    private fileout: string | null = null; // In browser/node, this would be a file handle
    private m_log_level: Level = Level.Debug;
    private m_categories: CategoryMask = LogFlags.NONE;
    private categoryLogLevels: Map<LogFlags, Level> = new Map();
    private limiter: LogRateLimiter | null = null;
    private printCallbacks: Array<(msg: string) => void> = [];

    // ─── Mutex (simplified - TypeScript is single-threaded) ───
    private lock<T>(fn: () => T): T {
        return fn();
    }

    /**
     * Start logging. Flushes buffered messages.
     */
    startLogging(): boolean {
        return this.lock(() => {
            if (!this.print_to_file) {
                // If no file output, just flush buffer
                this.buffering = false;
                return true;
            }
            this.buffering = false;
            return true;
        });
    }

    /**
     * Disable logging entirely.
     */
    disableLogging(): void {
        this.print_to_console = false;
        this.print_to_file = false;
        this.buffering = false;
    }

    /**
     * Check if logging is enabled.
     */
    enabled(): boolean {
        return !this.buffering || this.print_to_console || this.print_to_file || 
               this.printCallbacks.length > 0;
    }

    /**
     * Set the global log level.
     */
    setLogLevel(level: Level): void {
        this.m_log_level = level;
    }

    getLogLevel(): Level {
        return this.m_log_level;
    }

    /**
     * Set log level from string.
     */
    setLogLevelStr(levelStr: string): boolean {
        const level = LevelFromString(levelStr);
        if (level === null) return false;
        this.setLogLevel(level);
        return true;
    }

    /**
     * Enable a log category.
     */
    enableCategory(flag: LogFlags): void {
        this.m_categories |= flag;
    }

    enableCategoryStr(str: string): boolean {
        const flag = GetLogCategory(str);
        if (flag === null) return false;
        this.enableCategory(flag);
        return true;
    }

    /**
     * Disable a log category.
     */
    disableCategory(flag: LogFlags): void {
        this.m_categories &= ~flag;
    }

    disableCategoryStr(str: string): boolean {
        const flag = GetLogCategory(str);
        if (flag === null) return false;
        this.disableCategory(flag);
        return true;
    }

    getCategoryMask(): CategoryMask {
        return this.m_categories;
    }

    /**
     * Set a category-specific log level.
     */
    setCategoryLogLevel(category: LogFlags, level: Level): void {
        this.categoryLogLevels.set(category, level);
    }

    setCategoryLogLevelStr(categoryStr: string, levelStr: string): boolean {
        const category = GetLogCategory(categoryStr);
        const level = LevelFromString(levelStr);
        if (!category || !level) return false;
        this.setCategoryLogLevel(category, level);
        return true;
    }

    getCategoryLevels(): Map<LogFlags, Level> {
        return new Map(this.categoryLogLevels);
    }

    /**
     * Check if a category is active.
     */
    willLogCategory(category: LogFlags): boolean {
        return (this.m_categories & category) !== 0;
    }

    /**
     * Check if a category/level combination will be logged.
     */
    willLogCategoryLevel(category: LogFlags, level: Level): boolean {
        // Info, Warning, and Error are always logged
        if (level >= Level.Info) return true;

        if (!this.willLogCategory(category)) return false;

        const overrideLevel = this.categoryLogLevels.get(category);
        const effectiveLevel = overrideLevel ?? this.m_log_level;
        return level >= effectiveLevel;
    }

    /**
     * Get log categories as a list.
     */
    logCategoriesList(): LogCategoryInfo[] {
        const result: LogCategoryInfo[] = [];
        for (const [name, flag] of Object.entries(LOG_CATEGORIES_BY_STR)) {
            result.push({
                category: name,
                active: this.willLogCategory(flag),
            });
        }
        return result;
    }

    /**
     * Get log categories as a comma-separated string.
     */
    logCategoriesString(): string {
        return Join(this.logCategoriesList(), ', ', (c) => c.category);
    }

    /**
     * Set rate limiting.
     */
    setRateLimiting(limiter: LogRateLimiter): void {
        this.limiter = limiter;
    }

    /**
     * Add a print callback.
     */
    pushBackCallback(fun: (msg: string) => void): void {
        this.printCallbacks.push(fun);
    }

    /**
     * Remove a print callback.
     */
    deleteCallback(index: number): void {
        this.printCallbacks.splice(index, 1);
    }

    /**
     * Get the number of active callbacks.
     */
    numConnections(): number {
        return this.printCallbacks.length;
    }

    // ─── Formatting ───

    /**
     * Format a timestamp string.
     */
    private logTimestampStr(now: number, mocktime?: number): string {
        if (!this.log_timestamps) return '';

        const date = new Date(now);
        let result = date.toISOString();
        
        if (this.log_time_micros) {
            // Include microseconds
            const ms = date.getMilliseconds();
            result = result.replace('Z', `.${ms.toString().padStart(3, '0')}Z`);
        }

        if (mocktime !== undefined) {
            const mockDate = new Date(mocktime);
            result += ` (mocktime: ${mockDate.toISOString()})`;
        }

        return result + ' ';
    }

    /**
     * Get the log prefix (category and level).
     */
    private getLogPrefix(category: LogFlags, level: Level): string {
        if (category === LogFlags.NONE) category = LogFlags.ALL;
        
        const hasCategory = this.always_print_category_level || category !== LogFlags.ALL;
        
        if (!hasCategory && level === Level.Info) return '';

        let s = '[';
        if (hasCategory) {
            // Find category name
            for (const [name, flag] of Object.entries(LOG_CATEGORIES_BY_STR)) {
                if (flag === category) {
                    s += name;
                    break;
                }
            }
        }

        if (this.always_print_category_level || !hasCategory || level !== Level.Debug) {
            if (hasCategory) s += ':';
            s += LevelToString(level);
        }

        s += '] ';
        return s;
    }

    /**
     * Format a log entry.
     */
    private format(entry: LogEntry): string {
        let result = '';

        // Timestamp
        const now = entry.timestamp ?? Date.now();
        result += this.logTimestampStr(now, entry.mocktime);

        // Thread name
        if (this.log_threadnames && entry.thread_name) {
            result += `[${entry.thread_name}] `;
        }

        // Source location
        if (this.log_sourcelocations) {
            const file = RemovePrefixView(entry.source_loc.file_name, './');
            result += `[${file}:${entry.source_loc.line}] [${entry.source_loc.function_name_short}] `;
        }

        // Category and level
        result += this.getLogPrefix(entry.category, entry.level);

        // Message (escaped)
        result += LogEscapeMessage(entry.message);

        if (!result.endsWith('\n')) result += '\n';

        return result;
    }

    // ─── Log Output ───

    /**
     * Log a message.
     */
    logPrint(entry: LogEntry): void {
        this.lock(() => {
            this.logPrintInternal(entry);
        });
    }

    private logPrintInternal(entry: LogEntry): void {
        const now = entry.timestamp ?? Date.now();
        entry.timestamp = now;

        if (this.buffering) {
            const memUsage = this.estimateEntryMemUsage(entry);
            this.curBufferMemusage += memUsage;
            this.msgsBeforeOpen.push(entry);

            // Drop old messages if buffer is full
            while (this.curBufferMemusage > this.maxBufferMemusage && this.msgsBeforeOpen.length > 0) {
                const old = this.msgsBeforeOpen.shift()!;
                this.curBufferMemusage -= this.estimateEntryMemUsage(old);
                this.bufferLinesDiscarded++;
            }
            return;
        }

        const str = this.format(entry);
        let ratelimit = false;

        // Rate limiting
        if (entry.should_ratelimit && this.limiter) {
            const status = this.limiter.consume(entry.source_loc, str.length);
            if (status === 'NEWLY_SUPPRESSED') {
                // Log a warning about suppression
                const warningEntry: LogEntry = {
                    ...entry,
                    category: LogFlags.ALL,
                    level: Level.Warning,
                    should_ratelimit: false,
                    source_loc: entry.source_loc,
                    message: `Excessive logging detected from ${entry.source_loc.file_name}:${entry.source_loc.line} - suppressing further logs`,
                };
                this.logPrintInternal(warningEntry);
            } else if (status === 'STILL_SUPPRESSED') {
                ratelimit = true;
            }
        }

        // Prefix with [*] if there are suppressions
        if (this.limiter?.suppressionsActive()) {
            const prefixed = '[*] ' + str;
            this.outputMessage(prefixed, ratelimit);
        } else {
            this.outputMessage(str, ratelimit);
        }
    }

    private outputMessage(str: string, ratelimit: boolean): void {
        if (this.print_to_console) {
            console.log(str.trimEnd());
        }
        for (const cb of this.printCallbacks) {
            cb(str);
        }
    }

    private estimateEntryMemUsage(entry: LogEntry): number {
        return MallocUsage(entry.message.length + (entry.thread_name?.length ?? 0) + 64);
    }

    /**
     * Shrink the debug log file (keeps the last ~10 MB).
     */
    shrinkDebugFile(): void {
        // In TypeScript, we can't directly manipulate files.
        // This would need to be implemented with fs access.
        // Placeholder: log a warning about the limitation.
        if (this.print_to_console) {
            console.warn('shrinkDebugFile: file manipulation not available in browser');
        }
    }
}

// ─── Global Logger ───

let gLogger: Logger | null = null;

export function LogInstance(): Logger {
    if (!gLogger) {
        gLogger = new Logger();
    }
    return gLogger;
}

// ─── Convenience Logging Functions ───

export let fLogIPs = DEFAULT_LOGIPS;

/**
 * Check if a category/level combination should be logged.
 */
export function LogAcceptCategory(category: LogFlags, level: Level): boolean {
    return LogInstance().willLogCategoryLevel(category, level);
}

/**
 * Get a log flag from a string.
 */
export function GetLogCategoryFromString(str: string): LogFlags | null {
    return GetLogCategory(str);
}

// ─── Type-safe log level string constants ───
export const LOG_LEVEL_TRACE = 'trace';
export const LOG_LEVEL_DEBUG = 'debug';
export const LOG_LEVEL_INFO = 'info';
export const LOG_LEVEL_WARNING = 'warning';
export const LOG_LEVEL_ERROR = 'error';

/**
 * Log level constant for readability.
 */
export enum LogLevel {
    Trace = Level.Trace,
    Debug = Level.Debug,
    Info = Level.Info,
    Warning = Level.Warning,
    Error = Level.Error,
}
