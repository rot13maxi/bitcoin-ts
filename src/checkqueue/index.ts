// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Parallel check queue for script verification.
 * This is a TypeScript port of Bitcoin Core's checkqueue.h.
 * 
 * The check queue manages parallel execution of verification functions
 * (typically script checks) using a worker thread pool.
 * 
 * Port Layer 4: Memory/State - manages parallel validation resources.
 */

/**
 * Error type returned by check functions.
 * null means no error.
 */
export type CheckError = null | Error | string | number;

/**
 * A check function that returns an error or null on success.
 * The return type must be a CheckError (null for success, error otherwise).
 */
export type CheckFn<T> = () => CheckResult<T>;

/**
 * Result type for check functions.
 * null means the check passed.
 */
export type CheckResult<T> = T | CheckError;

/**
 * A batch of checks to be processed together.
 */
export interface CheckBatch<T> {
    checks: CheckFn<T>[];
}

/**
 * Configuration options for the check queue.
 */
export interface CheckQueueOptions {
    /** Maximum number of checks to process in one batch */
    batchSize?: number;
    /** Number of worker threads (0 = synchronous) */
    workerThreads?: number;
}

/**
 * Result of a Complete() operation on the check queue.
 * null means all checks passed.
 * Includes error types since checks can return errors.
 */
export type CheckQueueResult<T> = T | CheckError | null;

/**
 * Check queue for parallel verification.
 * 
 * This is a simplified TypeScript port. In the C++ version, the check queue
 * manages a pool of worker threads. In TypeScript, we simulate this behavior
 * using async/await with a limited concurrency semaphore.
 * 
 * Note: The actual parallel execution is simulated since JavaScript is
 * single-threaded. This implementation provides the correct interface
 * and sequential processing. For full parallelism, a Web Worker-based
 * implementation would be needed.
 */
export class CCheckQueue<T> {
    private queue: CheckFn<T>[] = [];
    private results: CheckQueueResult<T>[] = [];
    private running = false;
    private stopped = false;
    private readonly batchSize: number;
    private readonly workerCount: number;
    private activeWorkers = 0;
    private todo = 0;
    private completedPromise: Promise<CheckQueueResult<T>> | null = null;
    private resolveComplete: ((result: CheckQueueResult<T>) => void) | null = null;
    private rejectComplete: ((err: Error) => void) | null = null;

    /**
     * Create a new check queue.
     */
    constructor(options: CheckQueueOptions = {}) {
        this.batchSize = options.batchSize ?? 100;
        this.workerCount = options.workerThreads ?? 1;
    }

    /**
     * Get the number of pending checks.
     */
    size(): number {
        return this.queue.length + this.todo;
    }

    /**
     * Check if the queue has any workers.
     */
    hasThreads(): boolean {
        return this.workerCount > 0;
    }

    /**
     * Add a batch of checks to the queue.
     */
    add(vChecks: CheckFn<T>[]): void {
        if (vChecks.length === 0) return;

        for (const check of vChecks) {
            this.queue.push(check);
        }
        this.todo += vChecks.length;

        // If we have pending results to collect, the workers will pick them up
        // In a real implementation, we would notify worker threads here
    }

    /**
     * Wait for all queued checks to complete.
     * Returns the first error encountered, or null if all checks passed.
     */
    async complete(): Promise<CheckQueueResult<T>> {
        if (this.stopped) {
            return null;
        }

        // Process all checks sequentially (JavaScript is single-threaded)
        // In the C++ version, this would join the worker pool as the Nth worker
        while (this.todo > 0 || this.queue.length > 0) {
            // Process a batch
            const batchSize = Math.min(
                this.batchSize,
                Math.max(1, Math.floor(this.queue.length / (this.workerCount + 1)))
            );

            const batch: CheckFn<T>[] = [];
            for (let i = 0; i < batchSize && this.queue.length > 0; i++) {
                batch.push(this.queue.shift()!);
            }

            // Execute the batch
            for (const check of batch) {
                if (this.stopped) break;
                try {
                    const result = check();
                    if (result !== null) {
                        this.results.push(result);
                        this.todo--;
                        return result; // Early return on error
                    }
                } catch (e) {
                    this.results.push(e as CheckError);
                    this.todo--;
                    return e as CheckError;
                }
                this.todo--;
            }
        }

        // All checks passed
        return null;
    }

    /**
     * Stop the queue and cancel all pending checks.
     */
    stop(): void {
        this.stopped = true;
        this.queue = [];
    }

    /**
     * Destroy the queue, waiting for all workers to finish.
     */
    async destroy(): Promise<void> {
        this.stop();
        // In a real implementation, we would wait for worker threads to join
    }

    /**
     * Get all results collected so far.
     */
    getResults(): CheckQueueResult<T>[] {
        return [...this.results];
    }

    /**
     * Clear all collected results.
     */
    clearResults(): void {
        this.results = [];
    }
}

/**
 * RAII-style controller for CCheckQueue.
 * Guarantees Complete() is called when the controller goes out of scope.
 */
export class CCheckQueueControl<T> {
    private queue: CCheckQueue<T>;
    private done = false;
    private completedResult: CheckQueueResult<T> | null = null;

    constructor(queue: CCheckQueue<T>) {
        this.queue = queue;
    }

    /**
     * Complete the queue and return the result.
     */
    async complete(): Promise<CheckQueueResult<T>> {
        this.completedResult = await this.queue.complete();
        this.done = true;
        return this.completedResult;
    }

    /**
     * Add checks to the controlled queue.
     */
    add(vChecks: CheckFn<T>[]): void {
        this.queue.add(vChecks);
    }

    /**
     * Cleanup method - ensures complete() was called.
     * Alias for RAII-style resource management.
     */
    async dispose(): Promise<void> {
        if (!this.done) {
            await this.complete();
        }
    }
}

/**
 * Create a helper function for check queue usage.
 * Returns a function that wraps a check and returns null on success or an error on failure.
 */
export function makeCheck<T>(
    fn: () => T | null,
    errorValue: CheckError = null
): CheckFn<T> {
    return () => {
        try {
            const result = fn();
            if (result === null && errorValue !== null) {
                return errorValue;
            }
            return result;
        } catch (e) {
            return e as CheckError;
        }
    };
}
