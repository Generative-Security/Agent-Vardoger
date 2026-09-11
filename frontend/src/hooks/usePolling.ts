import { useCallback, useEffect, useRef, useState } from "react";

// usePolling: React hook that manages use polling state for callers.
export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number | null = 30000
): { data: T | null; loading: boolean; error: string; refetch: () => Promise<void> } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const mounted = useRef(true);

  const poll = useCallback(async () => {
      try {
        const result = await fetcher();
        if (mounted.current) {
          setData(result);
          setError("");
        }
      } catch (e: any) {
        if (mounted.current) setError(e.message || "Fetch failed");
      } finally {
        if (mounted.current) setLoading(false);
      }
  }, [fetcher]);

  useEffect(() => {
    mounted.current = true;
    let timer: ReturnType<typeof setInterval>;

    poll();
    if (intervalMs && intervalMs > 0) {
      timer = setInterval(poll, intervalMs);
    }
    return () => {
      mounted.current = false;
      clearInterval(timer);
    };
  }, [intervalMs, poll]);

  return { data, loading, error, refetch: poll };
}
