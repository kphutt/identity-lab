import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createCLI } from './cli.js';

describe('createCLI', () => {
  it('returns pause, explore, and close', () => {
    const cli = createCLI({ noPause: true });
    assert.equal(typeof cli.pause, 'function');
    assert.equal(typeof cli.explore, 'function');
    assert.equal(typeof cli.close, 'function');
    cli.close();
  });

  it('does not expose getChoice', () => {
    const cli = createCLI({ noPause: true });
    assert.equal(cli.getChoice, undefined);
    cli.close();
  });

  it('defaults noPause to false', () => {
    // No error when called without arguments
    const cli = createCLI();
    cli.close();
  });
});

describe('pause (noPause: true)', () => {
  it('resolves immediately', async () => {
    const cli = createCLI({ noPause: true });
    const result = cli.pause();
    assert.ok(result instanceof Promise);
    await result; // should not hang
    cli.close();
  });
});

describe('explore (noPause: true)', () => {
  let cli;
  let output;
  let originalLog;

  beforeEach(() => {
    cli = createCLI({ noPause: true });
    output = [];
    originalLog = console.log;
    console.log = (...args) => output.push(args.join(' '));
  });

  afterEach(() => {
    console.log = originalLog;
    cli.close();
  });

  it('runs all scenarios in order', async () => {
    const order = [];
    await cli.explore('Pick one:', [
      { name: 'First', fn: async () => order.push(1) },
      { name: 'Second', fn: async () => order.push(2) },
      { name: 'Continue', fn: async () => order.push(3) },
    ]);
    assert.deepEqual(order, [1, 2, 3]);
  });

  it('prints scenario headers with numbered labels', async () => {
    await cli.explore('Pick one:', [
      { name: 'Alpha', fn: async () => {} },
      { name: 'Continue', fn: async () => {} },
    ]);
    const headers = output.filter(l => l.includes('──'));
    assert.ok(headers.some(h => h.includes('[1]') && h.includes('Alpha')));
    assert.ok(headers.some(h => h.includes('[2]') && h.includes('Continue')));
  });

  it('handles a single scenario', async () => {
    const called = [];
    await cli.explore('Pick:', [
      { name: 'Only', fn: async () => called.push('only') },
    ]);
    assert.deepEqual(called, ['only']);
  });

  it('awaits async scenario functions', async () => {
    const timeline = [];
    await cli.explore('Pick:', [
      {
        name: 'Slow',
        fn: async () => {
          await new Promise(r => setTimeout(r, 10));
          timeline.push('slow');
        },
      },
      {
        name: 'Fast',
        fn: async () => { timeline.push('fast'); },
      },
    ]);
    assert.deepEqual(timeline, ['slow', 'fast']);
  });
});

describe('explore (noPause: false, interactive)', () => {
  it('exits when the last scenario is chosen', async () => {
    // Simulate user typing "2\n" to pick the last (Continue) option
    const { Readable } = await import('node:stream');
    const input = new Readable({ read() {} });

    // We need to create a CLI with a custom stdin that feeds "2\n"
    // Since createCLI uses process.stdin, we test the interactive path
    // by importing createInterface directly. This test verifies the
    // contract: choosing the last scenario breaks the loop.

    // For this we'll use a more targeted approach — mock stdin
    const originalStdin = process.stdin;
    const mockStdin = new Readable({ read() {} });
    Object.defineProperty(process, 'stdin', { value: mockStdin, writable: true });

    const cli = createCLI({ noPause: false });
    const originalLog = console.log;
    console.log = () => {};

    const scenarios = [
      { name: 'Option A', fn: async () => {} },
      { name: 'Continue', fn: async () => {} },
    ];

    const explorePromise = cli.explore('Pick:', scenarios);

    // Feed "2\n" to select Continue (the last option)
    mockStdin.push('2\n');

    await explorePromise;

    console.log = originalLog;
    cli.close();
    Object.defineProperty(process, 'stdin', { value: originalStdin, writable: true });
  });
});
