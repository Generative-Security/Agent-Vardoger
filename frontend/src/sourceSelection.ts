// Source selection persistence.
//
// A "source" is "<aws_account_id>/<agent>" — a SEGMENTATION filter within the
// single self-hosted scope. An empty string means "All sources" (the rollup).
// The selected source is persisted so monitoring pages stay in sync, and a
// custom event lets any listening picker react to changes elsewhere in the app.
const SELECTED_SOURCE_KEY = "vardoger.selectedSource";
export const SELECTED_SOURCE_EVENT = "vardoger:selectedSourceChanged";

// getSelectedSource: Returns the persisted source filter ("" = all sources).
export function getSelectedSource() {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(SELECTED_SOURCE_KEY) || "";
}

// setSelectedSource: Persists the source filter and notifies listeners.
export function setSelectedSource(source: string) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(SELECTED_SOURCE_KEY, source);
  window.dispatchEvent(new CustomEvent(SELECTED_SOURCE_EVENT, { detail: source }));
}
