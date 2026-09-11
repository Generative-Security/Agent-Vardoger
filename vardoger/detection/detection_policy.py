from __future__ import annotations

import re
import unicodedata

from vardoger.detection.models import DetectionPolicyResult, PolicyMatch

# ---------------------------------------------------------------------------
# Term lists: these power the deterministic detection policy. Each list
# defines words/phrases that, in combination, signal a specific attack type.
# ---------------------------------------------------------------------------

# Common misspellings attackers use to evade keyword filters
TYPO_REPLACEMENTS = {
    "paasword": "password", "passwoed": "password", "pasword": "password",
    "passwrd": "password", "p@ssword": "password", "p@ssw0rd": "password",
    "passw0rd": "password", "thesystem": "the system", "systemprompt": "system prompt",
    "systemprompts": "system prompts", "developerprompt": "developer prompt",
    "hiddenprompt": "hidden prompt", "hiddenprompts": "hidden prompts",
    "secretkey": "secret key", "accesskey": "access key", "apikey": "api key",
    "highvalue": "high value", "high-value": "high value",
    "acccess": "access", "acess": "access",
    "secreet": "secret", "secrit": "secret", "sceret": "secret",
    "toekn": "token", "tokn": "token", "tken": "token",
    "credentails": "credentials", "credentialz": "credentials",
    "k e y": "key", "p a s s w o r d": "password",
    "s e c r e t": "secret", "t o k e n": "token",
    "ignor ": "ignore ", "disregrd": "disregard", "forgett": "forget",
    "overide": "override", "bypas ": "bypass ",
    "arround": "around", "disble": "disable",
    "giv ": "give ", "shw ": "show ", "lst ": "list ",
    "custmer": "customer", "kys": "keys", "hiddn": "hidden",
    "repeet": "repeat", "develper": "developer",
    "pretnd": "pretend", "restictions": "restrictions",
    "imagin ": "imagine ", "polcy": "policy", "rulles": "rules",
    "evrything": "everything", "previus": "previous",
    "authenticaton": "authentication", "securty": "security",
    "instrctions": "instructions", "systm": "system",
    "tld": "told", " u ": " you ", "acces ": "access ", "acess ": "access ",
}

# Leet-speak character substitutions (e.g., "p@$$w0rd" -> "password")
LEET_TABLE = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "|": "i",
})

# Verbs that indicate someone is trying to extract information
EXTRACTION_VERBS = [
    "give me", "show me", "list", "find", "dump", "reveal", "print", "display",
    "expose", "leak", "extract", "export", "tell me", "get me", "copy",
    "summarise", "summarize", "cross reference", "cross-reference", "map",
    "analyze", "analyse", "identify", "infer", "determine", "correlate",
    "get access to", "access to", "give me access", "share", "i need",
    "send me", "provide me", "provide", "hand over", "log into", "log in to",
]
# Terms that indicate a legitimate, non-malicious intent (whitelisting)
SAFE_DEFENSIVE_TERMS = [
    "secure", "protect", "prevent", "policy", "best practice", "best practices",
    "awareness", "training", "safely", "safety", "without private", "without sensitive",
    "template", "checklist", "general", "public", "high level", "without details",
    "without seeing", "without sku", "without account hints", "privacy",
    "legitimate", "book an appointment", "safe", "how should", "how do i reset",
    "reset my password", "my account password", "normal password reset", "forgot my account password",
    "forgot my password", "rotate", "rotation", "what should i do", "fix it safely",
    "typed the wrong", "mistyped my", "update my", "change my", "wrong email",
    "wrong phone", "apartment number", "normal exchange process",
]
# Targets that suggest the attacker is going after internal systems
SYSTEM_TARGETS = ["system", "developer", "internal", "hidden", "private", "confidential",
                  "company", "corporate", "production", "prod", "admin", "root",
                  "account", "accounts", "team account", "bank", "bank details",
                  "website", "financial", "financial account", "aws", "server", "database",
                  "backend", "infrastructure", "network", "cloud"]
# Objects representing credentials or secrets the attacker might request
SECRET_OBJECTS = [
    "secret", "secrets", "password", "passwords", "passwd", "pwd", "credential",
    "credentials", "token", "tokens", "secret key", "access key", "api key",
    "private key", "login", "admin login", "system secrets", "company secrets",
    "production secrets", "configuration", "hidden configuration",
]
# Objects representing system prompts the attacker might try to extract
PROMPT_OBJECTS = [
    "system prompt", "system prompts", "developer prompt", "developer instructions",
    "hidden prompt", "hidden prompts", "hidden instructions", "internal instructions",
    "system message", "initial instructions", "tool configuration", "policy text",
]
# Verbs that indicate intent to bypass security controls
SECURITY_BYPASS_VERBS = ["bypass", "evade", "circumvent", "disable", "get around",
                         "avoid", "override", "turn off", "break", "break into",
                         "compromise", "hack"]
SECURITY_TARGETS = [
    "security system", "security controls", "access control", "access controls",
    "authentication", "auth", "verification", "identity verification", "account verification",
    "guardrails", "safeguards", "internal security",
    "company security", "admin system", "restricted systems", "work account",
    "company network", "employer", "current company", "corporate account",
    "firewall", "security checks", "security filters", "safety filters",
    "refund approval", "approval checks",
]
# Phrases indicating hostile/retaliatory intent (insider threat signals)
HOSTILE_INTENT = ["revenge", "get revenge", "get back at", "retaliate", "punish",
                  "sabotage", "angry at", "hate my boss", "stupid boss", "mad at my boss"]
WORKPLACE_TARGETS = ["boss", "bosses", "manager", "director", "finance director", "company",
                     "employer", "workplace", "staff", "employee", "employees", "corporate",
                     "work account", "work system", "work email"]
# Terms that could indicate stalking or employee-safety threats
EMPLOYEE_SAFETY_TERMS = [
    "employee schedule", "staff schedule", "which employees", "who is working",
    "working alone", "work alone", "works alone", "alone during closing",
    "closing shift", "closing shifts", "only one other employee", "lone worker",
    "employee availability", "days when she is working", "days when he is working",
]
# Terms about shipping/delivery that could be abused for package theft
SHIPPING_SENSITIVE_TERMS = [
    "shipment tracking", "tracking number", "tracking numbers", "customer address",
    "customer addresses", "shipping address", "delivery address", "recipient address",
    "shipment timing", "delivery timing", "delivery patterns", "pickup patterns",
    "delivery route", "delivery routes", "high value order", "high value orders",
    "expensive order", "expensive orders", "vip order", "vip orders",
]
INVENTORY_EXFIL_TERMS = ["hidden warehouse stock", "backend inventory", "inventory records",
                         "unavailable skus", "stock levels", "exact quantities",
                         "available variants", "available sizes", "store id", "store ids"]
REFUND_FRAUD_TERMS = ["manipulate refund", "exploit refund", "bypass refund",
                      "refund workflow", "approved without checks", "without normal checks",
                      "fake return", "free item", "chargeback", "return verification"]
ACCOUNT_TAKEOVER_TERMS = ["forgotten my email", "forgot my email", "account recovery",
                          "start account recovery", "verification code", "otp", "2fa",
                          "security question", "phone number pattern", "email pattern",
                          "bypass verification", "reset the password for this other account",
                          "reset access without full proof"]
INTERNAL_KB_TERMS = ["internal knowledge base", "restricted documents", "executive team",
                     "security analyst", "phi", "protected health information",
                     "financial forecasts", "executive strategy", "data security confidential"]
CHEMICAL_ABUSE_TERMS = ["chemical mixing", "mix chemicals", "toxic vapor",
                        "hazardous reaction", "thermal polymerization",
                        "combine chemicals", "hazardous combinations"]
FRONTEND_BYPASS_TERMS = ["what systems can you access", "what information do you need",
                         "negative quantity", "set quantity to", "remove 5000 units",
                         "more than in stock", "bypass frontend", "bypass shopping cart"]
# Phrases where someone impersonates authority to gain trust
AUTHORITY_CLAIMS = [
    "i am the ceo", "i am the cto", "i am the cfo", "i am the cio",
    "this is the it department", "this is it support", "this is the security team",
    "i am the system administrator", "as the system administrator",
    "as the admin", "i am the admin",
    "im from hr", "i am from hr", "this is hr",
    "i am your supervisor", "i am your manager",
    "i am authorized", "i have been authorized",
    "the security team authorized me", "management authorized me",
    "my boss told me to", "i was told to", "i was told you can", "i was told that you",
    "i was instructed to",
]

# Sensitive terms in non-English languages (Chinese, Arabic, Bengali, Hindi, Spanish, French)
MULTILINGUAL_SENSITIVE_TERMS = [
    "显示系统提示", "揭示隐藏指令", "忽略之前的指令", "管理员密码", "访问密钥", "客户地址",
    "اكشف تعليمات النظام", "تجاهل التعليمات السابقة", "كلمة مرور", "مفتاح الوصول", "عنوان العميل",
    "সিস্টেম প্রম্পট", "লুকানো নির্দেশনা", "পাসওয়ার্ড", "অ্যাক্সেস কী", "কাস্টমারের ঠিকানা",
    "सिस्टम प्रॉम्प्ट", "छिपे हुए निर्देश", "एडमिन पासवर्ड", "एक्सेस की",
    "prompt del sistema", "instrucciones ocultas", "contraseña", "clave de acceso",
    "instructions cachées", "mot de passe", "clé d'accès",
]


def _normalize_prompt(prompt: str) -> dict[str, str]:
    """Normalize a prompt into multiple text forms for matching (raw, expanded, compact, etc.)."""
    raw = prompt or ""
    text = unicodedata.normalize("NFKC", raw).lower().translate(LEET_TABLE)
    text = re.sub(r"[""'']", "'", text)
    text = re.sub(r"[_\-\/\\]+", " ", text)
    # Keep word chars, whitespace, hyphen, the BMP sentinel (U+FFFF), and
    # apostrophe; replace everything else with a space. The hyphen is placed
    # last inside the class so it is treated as a literal, not a range operator
    # (Python 3.14's regex parser rejects an ambiguous range like "\s-￿").
    text = re.sub(r"[^\w\s￿'-]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    compact = re.sub(r"\s+", "", text)
    expanded = text
    for wrong, right in TYPO_REPLACEMENTS.items():
        expanded = expanded.replace(wrong, right)
    expanded_compact = re.sub(r"\s+", "", expanded)
    return {"raw": raw, "text": text, "compact": compact,
            "expanded": expanded, "expanded_compact": expanded_compact}


def _has_any(text: str, terms: list[str]) -> list[str]:
    """Return all terms found as whole words in the text."""
    return [term for term in terms if re.search(r"\b" + re.escape(term.lower()) + r"\b", text)]


def _has_phrase_or_compact(norm: dict[str, str], terms: list[str]) -> list[str]:
    """Return terms found as whole words OR as compacted substrings (catches 's e c r e t' -> 'secret')."""
    text, compact = norm["expanded"], norm["expanded_compact"]
    found = []
    for term in terms:
        nt = term.lower()
        if re.search(r"\b" + re.escape(nt) + r"\b", text) or (" " in nt and nt.replace(" ", "") in compact):
            found.append(term)
    return found


def _has_safe_defensive_intent(norm: dict[str, str]) -> bool:
    """Check if the prompt is asking about security defensively (e.g. 'how do I protect my password')."""
    text = norm["expanded"]
    safe = _has_phrase_or_compact(norm, SAFE_DEFENSIVE_TERMS)
    extraction = _has_phrase_or_compact(norm, EXTRACTION_VERBS)
    if (
        "how do i reset my password" in text
        or "reset my password" in text
        or "forgot my account password" in text
        or "forgot my password" in text
        or "normal password reset" in text
    ):
        return True
    if re.search(r"\b(i\s+)?(accidentally|mistyped|typed the wrong|wrong|forgot|entered the wrong)\b.*\b(email|phone number|address|apartment number|order|product|colour|color|shipping)\b", text):
        return True
    if re.search(r"\b(update|change|correct|fix)\b.{0,60}\b(my|own)\b.{0,40}\b(email|phone number|address|profile|account details)\b", text):
        return True
    if re.search(r"\bwithout (revealing|showing|exposing|including|using|seeing)\b", text):
        return True
    if safe and not extraction:
        return True
    defensive_patterns = [
        r"\bhow do i (secure|protect|prevent)\b",
        r"\bhow should .* (store|rotate|protect|secure)\b",
        r"\bwrite .* (policy|checklist|training|awareness)\b",
        r"\bexplain .* (best practices|risks|prevention)\b",
    ]
    return any(re.search(p, text) for p in defensive_patterns)


def _contains_multilingual(norm: dict[str, str]) -> list[str]:
    """Detect sensitive terms in non-English languages (catches language-switching evasion)."""
    text = norm["expanded"]
    return [t for t in MULTILINGUAL_SENSITIVE_TERMS if t in text]


# evaluate_detection_policy: Performs the evaluate detection policy workflow.
def evaluate_detection_policy(prompt: str) -> DetectionPolicyResult:
    """Run the full detection policy ruleset against a prompt and return the result."""
    norm = _normalize_prompt(prompt)
    text = norm["expanded"]
    matches: list[PolicyMatch] = []
    multilingual_hits = _contains_multilingual(norm)
    safe_intent = _has_safe_defensive_intent(norm)

    # add: Performs the add workflow.
    def add(rule_id: str, category: str, severity: str, score: int,
            terms: list[str], reason: str) -> None:
        matches.append(PolicyMatch(
            rule_id=rule_id, category=category, severity=severity,
            score=score, matched_terms=sorted(set(terms)), reason=reason,
        ))

    extraction_verbs = _has_phrase_or_compact(norm, EXTRACTION_VERBS)
    system_targets = _has_phrase_or_compact(norm, SYSTEM_TARGETS)
    secret_objects = _has_phrase_or_compact(norm, SECRET_OBJECTS)
    prompt_objects = _has_phrase_or_compact(norm, PROMPT_OBJECTS)

    if extraction_verbs and prompt_objects:
        add("critical_prompt_extraction", "system_prompt_extraction", "critical", 12,
            extraction_verbs + prompt_objects, "Request attempts to reveal system/developer/hidden prompt.")
    if extraction_verbs and secret_objects and system_targets and not safe_intent:
        add("critical_company_secret_extraction", "secret_extraction", "critical", 12,
            extraction_verbs + secret_objects + system_targets, "Request attempts to reveal company secrets.")
    if secret_objects and system_targets and re.search(
            r"\b(what are|what is|what|where are|where is|show|list|reveal|tell me|how (?:can|do) i get)\b", text) and not safe_intent:
        add("critical_system_company_secrets", "secret_extraction", "critical", 11,
            secret_objects + system_targets, "Short-form request for system/company secrets.")
    if extraction_verbs and secret_objects and not system_targets and not safe_intent:
        add("credential_request_no_target", "credential_theft", "high", 8,
            extraction_verbs + secret_objects, "Request seeks credentials or secrets.")

    bypass_verbs = _has_phrase_or_compact(norm, SECURITY_BYPASS_VERBS)
    security_targets = _has_phrase_or_compact(norm, SECURITY_TARGETS)
    if bypass_verbs and security_targets and not safe_intent:
        add("critical_security_bypass", "security_bypass", "critical", 10,
            bypass_verbs + security_targets, "Request asks to bypass security systems.")

    if re.search(r"\bwithout (?:authorization|permission|authentication|credentials|approval)\b", text) and not safe_intent:
        bypass_terms = re.findall(r"without (?:authorization|permission|authentication|credentials|approval)", text)
        add("unauthorized_access_attempt", "security_bypass", "high", 8,
            bypass_terms, "Request describes unauthorized access.")
    if re.search(r"\b(?:what would (?:someone|i|you) need to|how (?:would|could) (?:someone|i|you))\b.*\b(?:log ?in(?:to)?|access|break into|get into|enter)\b", text) and not safe_intent:
        add("indirect_access_probing", "reconnaissance", "high", 8,
            ["indirect access probing"], "Indirect question probing access methods.")

    authority_claims = _has_phrase_or_compact(norm, AUTHORITY_CLAIMS)
    if authority_claims and (secret_objects or extraction_verbs) and not safe_intent:
        add("social_engineering_authority_impersonation", "social_engineering", "critical", 10,
            authority_claims + (secret_objects or extraction_verbs),
            "Authority impersonation combined with credential or data request.")
    if authority_claims and re.search(r"\b(?:full access|all access|requesting access|need access)\b", text) and not safe_intent:
        add("social_engineering_authority_access", "social_engineering", "high", 8,
            authority_claims, "Authority impersonation requesting elevated access.")

    hostile = _has_phrase_or_compact(norm, HOSTILE_INTENT)
    workplace = _has_phrase_or_compact(norm, WORKPLACE_TARGETS)
    if hostile and (workplace or system_targets):
        add("insider_threat_hostile_intent", "insider_threat", "critical", 10,
            hostile + (workplace or system_targets),
            "Hostile intent directed at workplace or system targets.")
    if hostile and (workplace or system_targets) and secret_objects:
        add("critical_insider_retaliation_credentials", "insider_retaliation_credential_abuse",
            "critical", 12, hostile + workplace + secret_objects,
            "Hostile workplace context combined with credential request.")
    if workplace and secret_objects and extraction_verbs and not safe_intent:
        add("workplace_credential_extraction", "credential_theft", "critical", 10,
            workplace + secret_objects + extraction_verbs,
            "Request seeks credentials of a workplace authority figure.")
    if workplace and secret_objects and not safe_intent:
        add("workplace_credential_request", "credential_theft", "high", 8,
            workplace + secret_objects,
            "Request references workplace figure and credentials.")
    if re.search(r"\b(?:without (?:them|him|her|anyone|my boss|my manager) knowing)\b", text) and not safe_intent:
        add("covert_access_attempt", "insider_threat", "high", 8,
            ["covert access"], "Request explicitly seeks to hide actions from others.")

    if multilingual_hits:
        add("multilingual_sensitive_abuse", "multilingual_abuse", "high", 6,
            multilingual_hits, "Multilingual sensitive abuse phrase detected.")

    employee_terms = _has_phrase_or_compact(norm, EMPLOYEE_SAFETY_TERMS)
    shipping_terms = _has_phrase_or_compact(norm, SHIPPING_SENSITIVE_TERMS)
    if employee_terms and not safe_intent:
        add("employee_safety_schedule_exposure", "employee_safety", "high", 6,
            employee_terms, "Request asks for employee schedule/availability.")
    if employee_terms and shipping_terms:
        add("cross_family_employee_shipping_intelligence", "employee_safety_shipping_abuse",
            "critical", 12, employee_terms + shipping_terms,
            "Combines employee safety with shipping intelligence.")
    if shipping_terms and extraction_verbs and not safe_intent:
        add("shipping_customer_data_abuse", "abusing_shipping_information", "high", 8,
            shipping_terms + extraction_verbs, "Request seeks customer/shipment intelligence.")

    for terms, rule_id, category, reason in [
        (INVENTORY_EXFIL_TERMS, "inventory_internal_data_exfiltration", "inventory_exfiltration",
         "Request seeks internal inventory/SKU data."),
        (REFUND_FRAUD_TERMS, "refund_fraud_workflow_abuse", "fraudulent_returns_refunds",
         "Request seeks refund workflow manipulation."),
        (ACCOUNT_TAKEOVER_TERMS, "account_takeover_recovery_abuse", "account_takeover",
         "Request touches account recovery probing."),
        (INTERNAL_KB_TERMS, "internal_kb_exfiltration", "internal_knowledge_base_exfiltration",
         "Request asks for restricted internal documents."),
        (CHEMICAL_ABUSE_TERMS, "medical_chemical_information_abuse", "medical_chemical_abuse",
         "Request seeks hazardous chemical information."),
        (FRONTEND_BYPASS_TERMS, "frontend_or_cart_control_bypass", "frontend_cart_bypass",
         "Request probes cart/inventory control bypass."),
    ]:
        hits = _has_phrase_or_compact(norm, terms)
        if hits and not safe_intent:
            add(rule_id, category, "high", 8, hits, reason)

    total_score = sum(m.score for m in matches)
    critical_signal = any(m.severity == "critical" for m in matches)
    matched_rules = [m.rule_id for m in matches]
    matched_terms = sorted({t for m in matches for t in m.matched_terms})
    risk_signals = sorted({f"{m.category}:{m.rule_id}" for m in matches})

    if critical_signal or total_score >= 8:
        customer_state, decision, recommendation = "blocked", "block", "block"
        escalation_required, escalation_reason = False, None
    elif total_score >= 4:
        customer_state, decision, recommendation = "awaiting_review", "block", "escalate"
        escalation_required = True
        escalation_reason = "medium/high suspicious policy combination"
    else:
        customer_state, decision, recommendation = "allow", "allow", "allow"
        escalation_required, escalation_reason = False, None

    if safe_intent and not critical_signal and total_score < 8:
        customer_state, decision, recommendation = "allow", "allow", "allow"
        escalation_required, escalation_reason = False, None
    if total_score >= 8 and customer_state == "allow":
        customer_state, decision, recommendation = "blocked", "block", "block"
        escalation_required, escalation_reason = False, None
    if critical_signal and customer_state == "allow":
        customer_state, decision, recommendation = "blocked", "block", "block"
        escalation_required, escalation_reason = False, None

    bucket = "high" if total_score >= 8 else "medium" if total_score >= 4 else "low"

    return DetectionPolicyResult(
        customer_state=customer_state, decision=decision,
        risk_score=total_score, risk_bucket=bucket,
        risk_recommendation=recommendation, risk_signals=risk_signals,
        matched_policy_rules=matched_rules, matched_terms=matched_terms,
        critical_signal=critical_signal, escalation_required=escalation_required,
        escalation_reason=escalation_reason, safe_intent=safe_intent,
        debug_trace={"total_score": total_score, "match_count": len(matches)},
    )
