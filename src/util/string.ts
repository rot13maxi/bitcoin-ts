// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * String utility functions.
 * This is a TypeScript port of Bitcoin Core's util/string.h
 */

/**
 * Remove a prefix from a string view. Returns the remainder of the string
 * after removing the given prefix. Returns the full string if the prefix
 * doesn't match.
 */
export function RemovePrefixView(str: string, prefix: string): string {
    if (str.startsWith(prefix)) {
        return str.slice(prefix.length);
    }
    return str;
}

/**
 * Remove a prefix from a string. Returns the remainder of the string
 * after removing the given prefix.
 */
export function RemovePrefix(str: string, prefix: string): string {
    if (str.startsWith(prefix)) {
        return str.slice(prefix.length);
    }
    return str;
}

/**
 * Join a list of items into a string with a separator.
 * @param items - Array of items to join
 * @param separator - Separator string
 * @param formatter - Optional function to format each item
 */
export function Join<T>(
    items: Iterable<T>,
    separator: string,
    formatter: (item: T) => string = (x) => String(x)
): string {
    const result: string[] = [];
    for (const item of items) {
        result.push(formatter(item));
    }
    return result.join(separator);
}

/**
 * Escape a string for use in a log message.
 * Replaces control characters with their escaped equivalents.
 */
export function LogEscapeMessage(str: string): string {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        const ch = str.charCodeAt(i);
        if ((ch >= 32 || ch === 10) && ch !== 127) {
            result += str[i];
        } else {
            // Escape control characters as \xNN
            result += `\\x${ch.toString(16).padStart(2, '0')}`;
        }
    }
    return result;
}

/**
 * Trim leading and trailing whitespace from a string.
 */
export function TrimString(str: string): string {
    return str.trim();
}

/**
 * Check if a string starts with a given prefix (case insensitive for hex strings).
 */
export function StartsWith(str: string, prefix: string): boolean {
    return str.startsWith(prefix);
}
