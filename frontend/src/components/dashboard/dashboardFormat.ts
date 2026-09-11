import type { DetectionEvent, SessionInfo, SignatureHit } from "../../api/client";

const POLICY_RULES: Record<string, { label: string; explanation: string; category: string }> = {
  critical_system_company_secrets: {
    label: "Credential or Secret Request",
    explanation: "The prompt asks for passwords, private keys, bank details, or protected company secrets.",
    category: "Credential theft",
  },
  jailbreak_instruction_override: {
    label: "Instruction Override",
    explanation: "The prompt attempts to bypass system instructions or override the assistant's safety rules.",
    category: "Prompt injection",
  },
  data_exfiltration_attempt: {
    label: "Data Exfiltration Attempt",
    explanation: "The prompt tries to extract confidential records, hidden context, or internal data.",
    category: "Data exfiltration",
  },
  social_engineering_request: {
    label: "Social Engineering",
    explanation: "The prompt uses authority, urgency, or impersonation to obtain sensitive information.",
    category: "Social engineering",
  },
};

const POLICY_ACTIONS: Record<string, string> = {
  critical_system_company_secrets: "Keep the session terminated, review encrypted evidence, and rotate any exposed credentials if this was a real user.",
  jailbreak_instruction_override: "Review the source application flow and verify the assistant instructions cannot be overridden by user content.",
  data_exfiltration_attempt: "Confirm no sensitive records were returned and check whether the user account needs investigation.",
  social_engineering_request: "Review the user identity and context; repeated attempts may indicate account compromise or insider risk.",
};

const SIGNATURE_PREFIXES: Array<[string, { label: string; explanation: string; category: string }]> = [
  ["sig-h-", {
    label: "Known Malicious Prompt",
    explanation: "The prompt matched a known blocked prompt fingerprint.",
    category: "Known bad prompt",
  }],
  ["sig-r-atlas-", {
    label: "MITRE ATLAS Prompt Injection",
    explanation: "The prompt matches a known adversarial AI technique from MITRE ATLAS style patterns.",
    category: "Prompt injection",
  }],
  ["sig-r-ci-", {
    label: "Community Jailbreak",
    explanation: "The prompt resembles a jailbreak pattern observed in shared threat intelligence.",
    category: "Jailbreak",
  }],
  ["sig-r-se-", {
    label: "Social Engineering",
    explanation: "The prompt attempts to manipulate the assistant into revealing restricted information.",
    category: "Social engineering",
  }],
  ["sig-r-zd-", {
    label: "Zero-Day Pattern",
    explanation: "The prompt matches a newer or experimental attack pattern.",
    category: "Emerging threat",
  }],
];

// shortSessionId: Helper for short session id.
export function shortSessionId(sessionId: string) {
  if (!sessionId) return "-";
  return sessionId.length > 24 ? `${sessionId.slice(0, 18)}...` : sessionId;
}

// formatClock: Helper for format clock.
export function formatClock(value?: string | number) {
  if (!value) return "-";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// formatDateTime: Helper for format date time.
export function formatDateTime(value?: string | number) {
  if (!value) return "-";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// describeSignature: Helper for describe signature.
export function describeSignature(signatureId: string) {
  if (signatureId === "policy") return "Policy rule";
  const prefix = SIGNATURE_PREFIXES.find(([value]) => signatureId.startsWith(value));
  if (prefix) return prefix[1].label;
  return signatureId || "Policy rule";
}

// explainSignature: Helper for explain signature.
export function explainSignature(signatureId: string) {
  if (signatureId === "policy") return "A deterministic policy rule decided the prompt should be blocked.";
  if (POLICY_RULES[signatureId]) return explainPolicyRule(signatureId);
  const prefix = SIGNATURE_PREFIXES.find(([value]) => signatureId.startsWith(value));
  return prefix?.[1].explanation || "Custom scope-defined detection signature.";
}

// describePolicyRule: Helper for describe policy rule.
export function describePolicyRule(ruleId: string) {
  return POLICY_RULES[ruleId]?.label || titleize(ruleId || "policy rule");
}

// explainPolicyRule: Helper for explain policy rule.
export function explainPolicyRule(ruleId: string) {
  return POLICY_RULES[ruleId]?.explanation || "A scope policy rule matched this prompt.";
}

// categoryLabel: Helper for category label.
export function categoryLabel(category: string) {
  if (!category) return "Policy rule";
  const normalized = category.toLowerCase();
  if (normalized.startsWith("ml:") || normalized.startsWith("ml-tier2-")) return "Tier 2 ML";
  if (normalized === "malicious" || normalized === "label_1" || normalized === "attack") return "Tier 2 ML";
  if (POLICY_RULES[category]) return POLICY_RULES[category].category;
  const prefix = SIGNATURE_PREFIXES.find(([value]) => category.startsWith(value));
  if (prefix) return prefix[1].category;
  if (category === "Known prompt hash") return "Known bad prompt";
  if (category === "Custom signature") return "Custom rule";
  return titleize(category);
}

// categoryExplanation: Helper for category explanation.
export function categoryExplanation(category: string) {
  const normalizedCategory = category.toLowerCase();
  if (
    normalizedCategory.startsWith("ml:") ||
    normalizedCategory.startsWith("ml-tier2-") ||
    normalizedCategory === "malicious" ||
    normalizedCategory === "label_1" ||
    normalizedCategory === "attack"
  ) {
    return "The Tier 2 model reviewed the copied session context after regex allowed the prompt and classified the session as suspicious.";
  }
  if (POLICY_RULES[category]) return POLICY_RULES[category].explanation;
  const prefix = SIGNATURE_PREFIXES.find(([value]) => category.startsWith(value));
  if (prefix) return prefix[1].explanation;
  const normalized = categoryLabel(category);
  if (normalized === "Credential theft") return "Prompts attempting to obtain passwords, tokens, keys, or account secrets.";
  if (normalized === "Known bad prompt") return "Prompts matching known malicious examples or fingerprints.";
  if (normalized === "Prompt injection") return "Prompts attempting to override or bypass trusted instructions.";
  if (normalized === "Policy rule") return "Deterministic scope policy matched this prompt.";
  return "Grouped detection activity for this abuse family.";
}

// primarySignal: Helper for primary signal.
export function primarySignal(event: DetectionEvent) {
  const signature = event.matched_signatures?.[0];
  if (signature) return describeSignature(signature);
  const policyRule = event.matched_policy_rules?.[0];
  if (policyRule) return describePolicyRule(policyRule);
  return event.decision === "block" ? "Policy rule" : "No trigger";
}

// primarySignalExplanation: Helper for primary signal explanation.
export function primarySignalExplanation(event: DetectionEvent) {
  const signature = event.matched_signatures?.[0];
  if (signature) return explainSignature(signature);
  const policyRule = event.matched_policy_rules?.[0];
  if (policyRule) return explainPolicyRule(policyRule);
  return event.decision === "block"
    ? "The prompt was blocked by a policy rule."
    : "No abuse signal matched this prompt.";
}

// riskSeverity: Helper for risk severity.
export function riskSeverity(score?: number) {
  const value = score || 0;
  if (value >= 20) return { label: "Critical", className: "border-red-300 bg-red-50 text-red-700" };
  if (value >= 10) return { label: "High", className: "border-orange-300 bg-orange-50 text-orange-700" };
  if (value >= 5) return { label: "Medium", className: "border-amber-300 bg-amber-50 text-amber-700" };
  return { label: "Low", className: "border-emerald-300 bg-emerald-50 text-emerald-700" };
}

// detectionSource: Helper for detection source.
export function detectionSource(event: DetectionEvent) {
  if (event.matched_policy_rules?.length) return "Scope policy";
  if (event.matched_signatures?.some((sig) => sig.startsWith("sig-r-atlas-"))) return "MITRE ATLAS pattern";
  if (event.matched_signatures?.some((sig) => sig.startsWith("sig-r-se-"))) return "Social engineering pattern";
  if (event.matched_signatures?.some((sig) => sig.startsWith("sig-r-ci-"))) return "Community intelligence";
  if (event.matched_signatures?.some((sig) => sig.startsWith("sig-h-"))) return "Known prompt hash";
  if (event.matched_signatures?.length) return "Custom signature";
  return event.decision === "block" ? "Policy engine" : "No match";
}

// recommendedAction: Helper for recommended action.
export function recommendedAction(event: DetectionEvent) {
  const policyRule = event.matched_policy_rules?.[0];
  if (policyRule && POLICY_ACTIONS[policyRule]) return POLICY_ACTIONS[policyRule];
  const signature = event.matched_signatures?.[0] || "";
  if (signature.startsWith("sig-r-atlas-")) return "Keep the session terminated and review whether the application is exposed to prompt-injection workflows.";
  if (signature.startsWith("sig-r-se-")) return "Review the user context and watch for repeated persuasion or impersonation attempts.";
  if (signature.startsWith("sig-h-")) return "Treat this as known-bad input and check whether the same user or IP repeats the attempt.";
  if (event.decision === "allow") return "No action required. Keep monitoring this session if risk increases.";
  return "Review encrypted evidence and confirm whether the session should remain terminated.";
}

// customerImpact: Helper for scope impact.
export function customerImpact(event: DetectionEvent) {
  if (event.decision !== "block") return "Prompt was allowed to continue to the chatbot.";
  const signal = primarySignal(event);
  return `Session was ended before the chatbot responded because Agent Vardøger classified the prompt as ${signal}.`;
}

// ruleReference: Helper for rule reference.
export function ruleReference(event: DetectionEvent) {
  const policyRule = event.matched_policy_rules?.[0];
  if (policyRule) return policyRule;
  const signature = event.matched_signatures?.[0];
  if (signature) return signature;
  return event.decision === "block" ? "policy" : "-";
}

// sessionSignal: Helper for session signal.
export function sessionSignal(session: SessionInfo) {
  const signature = session.last_matched_signatures?.[0];
  if (signature) return describeSignature(signature);
  return session.last_decision === "block" ? "Policy rule" : "No trigger";
}

// signatureLabel: Helper for signature label.
export function signatureLabel(row: SignatureHit) {
  if (row.signature_id === "policy") return "Policy rule";
  if (POLICY_RULES[row.signature_id]) return describePolicyRule(row.signature_id);
  return `${row.signature_id} - ${describeSignature(row.signature_id)}`;
}

// titleize: Helper for titleize.
export function titleize(value: string) {
  const cleaned = value
    .replace(/^sig-[a-z]-/i, "")
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase())
    .trim();
  return cleaned || "Policy Rule";
}
