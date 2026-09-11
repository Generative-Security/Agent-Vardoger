// LoadingSpinner: Renders the loading spinner UI section.
export default function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center py-12">
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-slate-200 border-t-slate-950" />
    </div>
  );
}
