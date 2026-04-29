// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin Core TypeScript Port
 */

// Re-export all modules
export * from './uint256';
export * from './arith_uint256';
export * from './primitives';
export * from './serialize';
export * from './span';
export * from './prevector';
export { tf_format as format } from './util';
export * from './tinyformat';
export * from './compat';
export * from './script/addresstype';

// Attributes - avoid naming conflicts
import * as attributesModule from './attributes';
export const {
    LIFETIMEBOUND: BTC_LIFETIMEBOUND,
    ALWAYS_INLINE: BTC_ALWAYS_INLINE,
    FALLTHROUGH: BTC_FALLTHROUGH,
    LIKELY: BTC_LIKELY,
    UNLIKELY: BTC_UNLIKELY,
    NOEXCEPT: BTC_NOEXCEPT,
    MAYBE_UNUSED: BTC_MAYBE_UNUSED,
    ARRAY_SIZE: BTC_ARRAY_SIZE,
    static_assert: BTC_static_assert
} = attributesModule;
