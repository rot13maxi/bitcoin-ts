// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Tiny format - a simple formatting utility.
 * This is a TypeScript port of Bitcoin Core's tinyformat.h.
 */

/**
 * Format a value according to the format string
 */
export function format(formatStr: string, ...args: unknown[]): string {
    let result = '';
    let argIndex = 0;
    let i = 0;

    while (i < formatStr.length) {
        // Check for format specifier
        if (formatStr[i] === '%') {
            i++;
            if (i >= formatStr.length) {
                result += '%';
                break;
            }

            // Handle %%
            if (formatStr[i] === '%') {
                result += '%';
                i++;
                continue;
            }

            // Parse format specifier: flags → width → precision → type
            let width = '';
            let precision = '';
            let type = 's';
            let explicitPrecision = false;
            let leftAlign = false;
            let showSign = false;
            let blankPositive = false;

            // Skip flags (-, +, space, #, 0)
            while (i < formatStr.length && /[-+ #0]/.test(formatStr[i])) {
                if (formatStr[i] === '-') leftAlign = true;
                if (formatStr[i] === '+') showSign = true;
                if (formatStr[i] === ' ') blankPositive = true;
                i++;
            }

            // Parse width (consecutive digits after flags)
            if (i < formatStr.length && formatStr[i] >= '0' && formatStr[i] <= '9') {
                while (i < formatStr.length && formatStr[i] >= '0' && formatStr[i] <= '9') {
                    width += formatStr[i];
                    i++;
                }
            }

            // Parse precision (decimal point followed by digits)
            if (i < formatStr.length && formatStr[i] === '.') {
                i++;
                explicitPrecision = true;
                while (i < formatStr.length && formatStr[i] >= '0' && formatStr[i] <= '9') {
                    precision += formatStr[i];
                    i++;
                }
            }

            // Get type character (if any)
            if (i < formatStr.length) {
                type = formatStr[i];
                i++;
            }

            // Get the argument
            if (argIndex >= args.length) {
                result += '?';
                continue;
            }

            const arg = args[argIndex++];
            result += formatValue(arg, type, parseInt(width) || 0, parseInt(precision) || 0, explicitPrecision, leftAlign, showSign, blankPositive);
        } else {
            result += formatStr[i];
            i++;
        }
    }

    return result;
}

/**
 * Format a single value according to its type specifier
 */
function formatValue(value: unknown, type: string, width: number, precision: number, explicitPrecision = false, leftAlign = false, showSign = false, blankPositive = false): string {
    let result = '';

    if (value === null) {
        result = 'null';
    } else if (value === undefined) {
        result = 'undefined';
    } else if (type === 's') {
        result = String(value);
    } else if (type === 'd' || type === 'i') {
        result = String(Math.round(Number(value)));
    } else if (type === 'u') {
        result = String(Math.abs(Math.round(Number(value))));
    } else if (type === 'x' || type === 'X') {
        result = Math.abs(Math.round(Number(value))).toString(16);
        if (type === 'X') {
            result = result.toUpperCase();
        }
    } else if (type === 'f') {
        const num = Number(value);
        if (precision > 0 || (precision === 0 && explicitPrecision)) {
            result = num.toFixed(precision);
        } else {
            // Default precision for 'f' is 6
            result = num.toFixed(6);
        }
        // Apply sign formatting for 'f' type
        if (type === 'f' && num >= 0) {
            if (showSign) {
                result = '+' + result;
            } else if (blankPositive) {
                result = ' ' + result;
            }
        }
    } else if (type === 'e' || type === 'E') {
        const num = Number(value);
        if (precision > 0 || (precision === 0 && explicitPrecision)) {
            result = num.toExponential(precision);
        } else {
            result = num.toExponential();
        }
        if (type === 'E') {
            result = result.toUpperCase();
        }
    } else if (type === 'g' || type === 'G') {
        const num = Number(value);
        if (precision > 0 || (precision === 0 && explicitPrecision)) {
            result = num.toPrecision(precision);
        } else {
            result = String(num);
        }
        if (type === 'G') {
            result = result.toUpperCase();
        }
    } else if (type === 'c') {
        result = String.fromCharCode(Math.round(Number(value)));
    } else if (type === 'p') {
        // Use BigInt to avoid precision loss for large pointer values
        const ptr = typeof value === 'bigint' ? value : BigInt(Number(value));
        result = '0x' + ptr.toString(16);
    } else if (type === 'a' || type === 'A') {
        // Address format
        const ptr = typeof value === 'bigint' ? value : BigInt(Number(value));
        result = '0x' + ptr.toString(16);
        if (type === 'A') {
            result = result.toUpperCase();
        }
    } else if (type === 'n') {
        result = String(value);
    } else if (type === 'a') {
        // Address format - treat as pointer
        result = '0x' + Number(value).toString(16);
    } else {
        // Default - use string conversion
        result = String(value);
    }

    // Apply width
    if (width > result.length) {
        const padding = ' '.repeat(width - result.length);
        if (leftAlign) {
            // Left-align
            result = result + padding;
        } else {
            // Right-align
            result = padding + result;
        }
    }

    return result;
}

/**
 * Printf-like function
 */
export function printf(formatStr: string, ...args: unknown[]): string {
    return format(formatStr, ...args);
}

/**
 * Format to a string and return it
 */
export function strprintf(formatStr: string, ...args: unknown[]): string {
    return format(formatStr, ...args);
}

/**
 * Make stream-like formatting object
 */
export class FormatWriter {
    private buffer: string[] = [];

    write(...args: unknown[]): void {
        for (const arg of args) {
            this.buffer.push(String(arg));
        }
    }

    flush(): string {
        const result = this.buffer.join('');
        this.buffer = [];
        return result;
    }

    str(): string {
        return this.buffer.join('');
    }
}

/**
 * Create a format object for chaining
 */
export function makeFormat(formatStr: string, ...args: unknown[]): FormatWriter {
    const writer = new FormatWriter();
    writer.write(format(formatStr, ...args));
    return writer;
}
