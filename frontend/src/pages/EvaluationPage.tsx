import { useEffect, useState } from "react";
import { evaluationApi, type EvaluationRunResponse, type EvaluationSummary } from "../api/client";
import { getSelectedSource } from "../sourceSelection";
import { useAuth } from "../auth";
import SourcePicker from "../components/shared/SourcePicker";

function ratio(numerator: number, denominator: number) {
  if (!denominator) return "-";
  return `${Math.round((numerator / denominator) * 100)}%`;
}

// EvaluationPage: Outcome-ledger TP/TN/FP/FN summary (all roles) and evaluation
// run trigger (admin). GET /api/evaluation, POST /api/evaluation/run.
export default function EvaluationPage() {
  const { hasRole } = useAuth();
  const canRun = hasRole("admin");
  const [source, setSource] = useState(getSelectedSource());
  const [summary, setSummary] = useState<EvaluationSummary | null>(null);
  const [run, setRun] = useState<EvaluationRunResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  async function loadSummary(nextSource = source) {
    setLoading(true);
    setError("");
    try {
      const response = await evaluationApi.summary(nextSource);
      setSummary(response.data);
    } catch {
      setError("Could not load the evaluation summary.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadSummary(source);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source]);

  async function triggerRun() {
    if (!canRun) return;
    setRunning(true);
    setError("");
    setRun(null);
    try {
      const response = await evaluationApi.run();
      setRun(response.data);
    } catch {
      setError("Could not trigger an evaluation run. Admin role is required.");
    } finally {
      setRunning(false);
    }
  }

  // Derived precision/recall from the summary counts.
  const tp = summary?.true_positive || 0;
  const fp = summary?.false_positive || 0;
  const fn = summary?.false_negative || 0;
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Admin</p>
          <h1 className="mt-1 text-3xl font-semibold text-slate-950">Evaluation</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Outcome-ledger accuracy for the scope — true/false positives and negatives, with derived precision and recall.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => loadSummary()} className="rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold text-slate-700">Refresh</button>
          {canRun && (
            <button onClick={triggerRun} disabled={running} className="rounded-md bg-slate-950 px-4 py-2 text-sm font-semibold text-white disabled:bg-slate-300">
              {running ? "Starting..." : "Run evaluation"}
            </button>
          )}
        </div>
      </div>

      <SourcePicker onSourceChange={setSource} />

      {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}
      {run && (
        <div className="rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
          Run {run.run_id} {run.status}. {run.detail}
        </div>
      )}
      {loading && !summary && <div className="rounded-lg border border-slate-200 bg-white p-8 text-sm text-slate-500 shadow-sm">Loading evaluation summary...</div>}

      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="Total" value={String(summary?.total || 0)} detail="Outcome-ledger rows" />
        <Metric label="TP / TN" value={`${summary?.true_positive || 0} / ${summary?.true_negative || 0}`} detail="Correct attack / benign" tone="green" />
        <Metric label="FP / FN" value={`${summary?.false_positive || 0} / ${summary?.false_negative || 0}`} detail="Needs analyst review" tone="red" />
        <Metric label="Unknown" value={String(summary?.unknown || 0)} detail="Unlabeled rows" />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Metric label="Precision" value={precision} detail="TP / (TP + FP)" />
        <Metric label="Recall" value={recall} detail="TP / (TP + FN)" />
      </div>

      <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950">Scope</h2>
        <p className="mt-2 text-sm text-slate-600">
          Scope: <span className="font-mono">{summary?.scope_id || "-"}</span>
          {source ? <> · Source: <span className="font-mono">{source}</span></> : <> · All sources</>}
        </p>
      </section>
    </div>
  );
}

function Metric({ label, value, detail, tone = "blue" }: { label: string; value: string; detail: string; tone?: "blue" | "red" | "green" }) {
  const color = tone === "red" ? "text-red-600" : tone === "green" ? "text-emerald-600" : "text-blue-600";
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-2 text-3xl font-semibold ${color}`}>{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </div>
  );
}
