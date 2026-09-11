import { ReactNode, useState } from "react";

interface Props {
  title: string;
  description?: string;
  children: ReactNode;
  actions?: ReactNode;
}

// DashboardPanel: Renders the dashboard panel UI section.
export default function DashboardPanel({ title, description, children, actions }: Props) {
  const [expanded, setExpanded] = useState(false);
  // content: Helper for content.
  const content = (
    <>
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-medium text-slate-700">{title}</div>
          {description && <div className="mt-1 text-xs text-slate-500">{description}</div>}
        </div>
        <div className="flex items-center gap-2">
          {actions}
          <button
            type="button"
            onClick={() => setExpanded(true)}
            className="rounded-md border border-slate-200 px-2 py-1 text-xs font-medium text-slate-500 hover:border-slate-300 hover:text-slate-800"
            title={`Open ${title} full screen`}
          >
            Expand
          </button>
        </div>
      </div>
      {children}
    </>
  );

  return (
    <>
      <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        {content}
      </section>
      {expanded && (
        <div className="fixed inset-0 z-50 bg-slate-950/40 p-4">
          <section className="flex h-full flex-col rounded-lg bg-white p-6 shadow-xl">
            <div className="mb-4 flex items-start justify-between gap-3 border-b border-slate-200 pb-4">
              <div>
                <div className="text-lg font-semibold text-slate-950">{title}</div>
                {description && <div className="mt-1 text-sm text-slate-500">{description}</div>}
              </div>
              <button
                type="button"
                onClick={() => setExpanded(false)}
                className="rounded-md border border-slate-200 px-3 py-2 text-sm font-medium text-slate-600 hover:border-slate-300 hover:text-slate-950"
              >
                Close
              </button>
            </div>
            <div className="dashboard-expanded min-h-0 flex-1 overflow-auto">{children}</div>
          </section>
        </div>
      )}
    </>
  );
}
