import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { useProtectedRead } from '../src/use-protected-read';
import { ApiError } from '../src/api';
function View({
  id,
  read,
  failed,
}: {
  id: string;
  read: (signal: AbortSignal) => Promise<string>;
  failed: (e: unknown) => void;
}) {
  const state = useProtectedRead(id, read, failed);
  return <div>{state.data ?? state.error ?? 'Loading'}</div>;
}
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});
it('does not accept an old response after navigation and aborts it on teardown', async () => {
  let first!: (value: string) => void, second!: (value: string) => void;
  const signals: AbortSignal[] = [];
  const read = vi.fn((signal: AbortSignal) => {
    signals.push(signal);
    return new Promise<string>((resolve) => {
      if (signals.length === 1) first = resolve;
      else second = resolve;
    });
  });
  const failed = vi.fn();
  const view = render(<View id="a" read={read} failed={failed} />);
  view.rerender(<View id="b" read={read} failed={failed} />);
  expect(signals[0]!.aborted).toBe(true);
  await act(async () => {
    first('OLD PRIVATE RECORD');
    await Promise.resolve();
  });
  expect(screen.queryByText('OLD PRIVATE RECORD')).toBeNull();
  await act(async () => {
    second('CURRENT RECORD');
    await Promise.resolve();
  });
  expect(screen.getByText('CURRENT RECORD')).toBeTruthy();
  view.unmount();
  expect(signals[1]!.aborted).toBe(true);
});
it('rechecks after 15 seconds without overlap and clears data on a revoked response', async () => {
  vi.useFakeTimers();
  let reject!: (error: unknown) => void;
  const read = vi
    .fn<(signal: AbortSignal) => Promise<string>>()
    .mockResolvedValueOnce('PRIVATE RECORD')
    .mockImplementation(
      () =>
        new Promise((_resolve, failed) => {
          reject = failed;
        }),
    );
  const failed = vi.fn();
  render(<View id="a" read={read} failed={failed} />);
  await act(async () => {
    await Promise.resolve();
  });
  expect(screen.getByText('PRIVATE RECORD')).toBeTruthy();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(15000);
  });
  expect(read).toHaveBeenCalledTimes(2);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(30000);
  });
  expect(read).toHaveBeenCalledTimes(2);
  await act(async () => {
    reject(new ApiError(401));
    await Promise.resolve();
  });
  expect(screen.queryByText('PRIVATE RECORD')).toBeNull();
  expect(failed).toHaveBeenCalledTimes(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(30000);
  });
  expect(read).toHaveBeenCalledTimes(2);
});

it('preserves keyboard focus through successful background revalidation', async () => {
  vi.useFakeTimers();
  const read = vi
    .fn<(signal: AbortSignal) => Promise<string>>()
    .mockResolvedValue('CURRENT RECORD');
  const failed = vi.fn();
  function FocusView() {
    const state = useProtectedRead('stable', read, failed);
    return (
      <>
        <button>Stable control</button>
        <p>{state.data}</p>
      </>
    );
  }
  render(<FocusView />);
  await act(async () => {
    await Promise.resolve();
  });
  const button = screen.getByRole('button', { name: 'Stable control' });
  button.focus();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(15000);
  });
  expect(document.activeElement).toBe(button);
  expect(read).toHaveBeenCalledTimes(2);
  expect(failed).not.toHaveBeenCalled();
});
