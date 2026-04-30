/**
 * Tests for tinyformat (printf-like formatting).
 *
 * Bugs:
 * - Float precision formatting produces wrong output (bi-kzq)
 * - Pointer formatting produces wrong output (bi-kzq)
 *
 * Reference: Bitcoin Core src/tinyformat.h
 */

import { describe, it, expect } from 'vitest';
import { format, printf, strprintf, FormatWriter, makeFormat } from '../tinyformat';

describe('tinyformat — format string basics', () => {
    it('formats single argument', () => {
        expect(format('hello %s', 'world')).toBe('hello world');
    });

    it('formats multiple arguments', () => {
        expect(format('%s %s', 'hello', 'world')).toBe('hello world');
    });

    it('escapes %% to a single %', () => {
        expect(format('100%%')).toBe('100%');
    });

    it('handles trailing %%', () => {
        expect(format('value=%%')).toBe('value=%');
    });

    it('passes through string without format specifier', () => {
        expect(format('no format')).toBe('no format');
    });
});

describe('tinyformat — integer formatting', () => {
    it('decimal %d', () => {
        expect(format('%d', 42)).toBe('42');
    });

    it('negative %d', () => {
        expect(format('%d', -42)).toBe('-42');
    });

    it('decimal %i', () => {
        expect(format('%i', 99)).toBe('99');
    });

    it('unsigned %u', () => {
        expect(format('%u', 100)).toBe('100');
    });

    it('hex lowercase %x', () => {
        expect(format('%x', 255)).toBe('ff');
    });

    it('hex uppercase %X', () => {
        expect(format('%X', 255)).toBe('FF');
    });

    it('hex with 0x prefix via %x', () => {
        // Note: %x itself doesn't add 0x — that's via %p or manual formatting
        expect(format('%x', 0xdeadbeef)).toBe('deadbeef');
    });
});

describe('tinyformat — float formatting (precision bug)', () => {
    it('%.2f formats to 2 decimal places', () => {
        expect(format('%.2f', 3.14159)).toBe('3.14');
    });

    it('%.3f adds trailing zeros', () => {
        expect(format('%.3f', 1.5)).toBe('1.500');
    });

    it('%.1f rounds correctly', () => {
        expect(format('%.1f', 2.345)).toBe('2.3');
    });

    it('%.0f formats with no decimal places', () => {
        expect(format('%.0f', 42.9)).toBe('43');
    });

    it('%.6f for small decimal', () => {
        expect(format('%.6f', 0.1)).toBe('0.100000');
    });

    it('%f without precision uses default', () => {
        // %f without precision should show a reasonable number of digits
        expect(format('%f', 3.14)).toBe('3.14');
    });

    it('%f for large numbers', () => {
        expect(format('%f', 1234567.89)).toBe('1234567.89');
    });

    it('%f for very small numbers', () => {
        expect(format('%f', 0.000001)).toBe('0.000001');
    });

    it('negative float %.2f', () => {
        expect(format('%.2f', -3.14159)).toBe('-3.14');
    });

    it('%.10f for 1/3 approximation', () => {
        expect(format('%.10f', 1 / 3)).toBe('0.3333333333');
    });
});

describe('tinyformat — scientific notation %e / %E', () => {
    it('%e lowercases exponent', () => {
        const result = format('%e', 123.456);
        expect(result).toMatch(/^1\.23456e\+0?5$/);
    });

    it('%E uppercases exponent marker', () => {
        const result = format('%E', 123.456);
        expect(result).toMatch(/^1\.23456E\+0?5$/);
    });

    it('%.3e with precision', () => {
        const result = format('%.3e', 123.456);
        expect(result).toMatch(/^1\.235e\+0?5$/);
    });
});

describe('tinyformat — %g / %G formatting', () => {
    it('%g for normal number', () => {
        expect(format('%g', 3.14)).toBe('3.14');
    });

    it('%G uses uppercase E', () => {
        const result = format('%G', 1e10);
        expect(result).toMatch(/E/);
    });
});

describe('tinyformat — pointer formatting (pointer bug)', () => {
    it('%p formats as 0x-prefixed hex', () => {
        expect(format('%p', 0x123abc)).toBe('0x123abc');
    });

    it('%p for address 0', () => {
        expect(format('%p', 0)).toBe('0x0');
    });

    it('%p for null-ish address', () => {
        expect(format('%p', null)).toBe('0x' + String(null).padStart(4, '0'));
    });

    it('%p for large pointer', () => {
        expect(format('%p', 0xdeadbeefn)).toBe('0xdeadbeef');
    });
});

describe('tinyformat — character %c', () => {
    it('%c formats single char', () => {
        expect(format('%c', 65)).toBe('A');
    });

    it('%c for lowercase letter', () => {
        expect(format('%c', 97)).toBe('a');
    });
});

describe('tinyformat — width padding', () => {
    it('%5d right-pads to width 5', () => {
        expect(format('%5d', 42)).toBe('   42');
    });

    it('%-5d left-pads to width 5', () => {
        expect(format('%-5d', 42)).toBe('42   ');
    });

    it('%05d zero-pads to width 5', () => {
        expect(format('%05d', 42)).toBe('00042');
    });
});

describe('tinyformat — %n (value of written chars)', () => {
    it('%n writes character count', () => {
        // %n is tricky — it writes to a passed pointer.
        // tinyformat's %n sets the int* arg to chars written so far.
        // This is not easily testable in pure TS, but we test it doesn't crash.
        const result = format('hello%nworld', 0);
        expect(result).toBe('helloworld');
    });
});

describe('tinyformat — FormatWriter', () => {
    it('FormatWriter.write appends strings', () => {
        const writer = new FormatWriter();
        writer.write('hello');
        writer.write(' ', 'world');
        expect(writer.str()).toBe('hello world');
    });

    it('FormatWriter.flush returns and clears buffer', () => {
        const writer = new FormatWriter();
        writer.write('test');
        const flushed = writer.flush();
        expect(flushed).toBe('test');
        expect(writer.str()).toBe('');
    });
});

describe('tinyformat — makeFormat', () => {
    it('makeFormat returns a writer with formatted content', () => {
        const writer = makeFormat('value: %d', 42);
        expect(writer.str()).toBe('value: 42');
    });
});

describe('tinyformat — printf / strprintf aliases', () => {
    it('printf is an alias for format', () => {
        expect(printf('%s %d', 'answer', 42)).toBe('answer 42');
    });

    it('strprintf is an alias for format', () => {
        expect(strprintf('%x', 0xff)).toBe('ff');
    });
});
