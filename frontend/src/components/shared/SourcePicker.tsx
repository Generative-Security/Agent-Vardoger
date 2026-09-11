import { useEffect, useState } from "react";
import { sourcesApi } from "../../api/client";
import { getSelectedSource, setSelectedSource } from "../../sourceSelection";

interface Props {
  // Notifies the parent when the selected source changes ("" = all sources).
  onSourceChange: (source: string) => void;
  // Compact variant is used inline in the top nav.
  compact?: boolean;
}

// SourcePicker: Dropdown that filters monitoring pages by source
// ("<aws_account_id>/<agent>"). An empty value means "All sources" (rollup).
export default function SourcePicker({ onSourceChange, compact = false }: Props) {
  const [sources, setSources] = useState<string[]>([]);
  const [source, setSource] = useState(getSelectedSource());
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    sourcesApi
      .list()
      .then((response) => {
        if (!alive) return;
        setSources(response.data.sources || []);
      })
      .catch(() => {
        if (alive) setError("Could not load sources.");
      });
    return () => {
      alive = false;
    };
  }, []);

  function change(next: string) {
    setSource(next);
    setSelectedSource(next);
    onSourceChange(next);
  }

  if (compact) {
    return (
      <label className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-500">
        Source
        <select
          value={source}
          onChange={(event) => change(event.target.value)}
          className="rounded-md border border-slate-200 bg-white px-2 py-1 text-sm text-slate-800 focus:border-slate-950 focus:outline-none"
        >
          <option value="">All sources</option>
          {sources.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
      </label>
    );
  }

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <label className="block text-sm font-semibold text-slate-700" htmlFor="source-picker">
        Source
      </label>
      <div className="mt-2 flex flex-col gap-3 md:flex-row md:items-center">
        <select
          id="source-picker"
          value={source}
          onChange={(event) => change(event.target.value)}
          className="min-w-72 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-950 shadow-sm focus:border-slate-950 focus:outline-none"
        >
          <option value="">All sources</option>
          {sources.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <p className="text-xs text-slate-500">
          Filter monitoring by "&lt;aws_account_id&gt;/&lt;agent&gt;". Empty shows the rollup across all sources.
        </p>
      </div>
      {error && <p className="mt-2 text-xs text-red-600">{error}</p>}
    </div>
  );
}
