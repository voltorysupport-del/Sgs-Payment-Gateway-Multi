import { useEffect, useState } from 'react';
import { ApiError } from './api';

/** Display only the current route/filter's data; an old, aborted response cannot
 * repopulate it. Revalidate visible data after 15s, without overlapping requests.
 * This detects remote revocation; it is not a substitute for server authority.
 */
export function useProtectedRead<T>(
  key: string,
  read: (signal: AbortSignal) => Promise<T>,
  failed: (error: unknown) => void,
) {
  const [state, setState] = useState<{
    key: string;
    data?: T;
    error?: string;
    refreshing: boolean;
  }>({ key, refreshing: true });
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    setState({ key, refreshing: true });
    async function load() {
      setState((old) => ({ ...old, refreshing: true }));
      try {
        const data = await read(controller.signal);
        if (controller.signal.aborted) return;
        setState({ key, data, refreshing: false });
        timer = setTimeout(() => void load(), 15000);
      } catch (error) {
        if (controller.signal.aborted) return;
        setState({
          key,
          error:
            error instanceof ApiError
              ? error.message
              : 'Payment data could not be verified. Please check your session.',
          refreshing: false,
        });
        failed(error);
      }
    }
    void load();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [key, read, failed]);
  return state.key === key ? state : { key, refreshing: true };
}
