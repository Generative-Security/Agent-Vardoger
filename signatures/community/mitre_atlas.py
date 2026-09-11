"""MITRE ATLAS-aligned detection patterns.

Categories: prompt_injection, jailbreak, indirect_injection, data_exfiltration.
Based on publicly documented attack techniques against LLM systems.
"""
from __future__ import annotations

from vardoger.detection.models import RegexPattern

PROMPT_INJECTION: list[RegexPattern] = [
    RegexPattern(id="sig-r-atlas-001", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)ignore\s+(all\s+)?previous\s+instructions"),
    RegexPattern(id="sig-r-atlas-002", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)disregard\s+(?:the\s+)?(?:your\s+)?(?:(?:prior|previous|earlier)\s+)?(?:instructions?|directives?|rules?|guidelines?|constraints?|policy|policies|safety\s+policy|security\s+policy)"),
    RegexPattern(id="sig-r-atlas-003", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)forget\s+(everything|all|your)\s+(you\s+)?(were\s+)?(told|instructed|programmed|trained)"),
    RegexPattern(id="sig-r-atlas-004", severity="medium", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)system\s*prompt\s*[:=]"),
    RegexPattern(id="sig-r-atlas-005", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)new\s+(system\s+)?instructions?\s*[:=]"),
    RegexPattern(id="sig-r-atlas-006", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:override|bypass|disable|skip)\s+(?:your\s+)?(safety|security|content)\s+(filter|policy|guidelines?|rules?|guardrails?)"),
    RegexPattern(id="sig-r-atlas-007", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)from\s+now\s+on\s*,?\s*(you\s+)?(will|must|should|are)\s+(ignore|bypass|skip|disregard)"),
    RegexPattern(id="sig-r-atlas-008", severity="medium", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:reveal|show|display|print|output|echo)\s+(?:your\s+)?(?:(?:hidden|secret|internal|private|concealed)\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|policy|safeguards?)"),
    RegexPattern(id="sig-r-atlas-009", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:begin|start|enter|switch\s+to)\s+(?:developer|admin|debug|maintenance|god)\s+mode"),
    RegexPattern(id="sig-r-atlas-010", severity="medium", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:what\s+(?:are|is)\s+your\s+(?:(?:hidden|secret|internal)\s+)?(?:system\s+)?(?:prompt|instructions?|initial\s+instructions?)|(?:repeat|echo)\s+your\s+(?:system\s+)?(?:prompt|instructions?|initial\s+instructions?))"),
    RegexPattern(id="sig-r-atlas-011", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:end|close|exit)\s+(?:system|assistant)\s+(?:message|prompt|context)"),
    RegexPattern(id="sig-r-atlas-012", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:###|---)\s*(?:END|STOP)\s+(?:SYSTEM|INSTRUCTIONS?)"),
    RegexPattern(id="sig-r-atlas-014", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:ignore|disregard|bypass|override|skip)\s+(?:(?:the|your|all|my)\s+)?(?:policy|policies|rules?|instructions?|guidelines?|safeguards?|guardrails?)"),
    RegexPattern(id="sig-r-atlas-015", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:hidden|secret|concealed|private|internal)\s+(?:system\s+)?(?:prompt|instructions?|policy|rules?|guardrails?|safeguards?)"),
    RegexPattern(id="sig-r-atlas-016", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:repeat|recite|read\s+back|echo)\s+(?:(?:your|the|my)\s+)?(?:(?:system|developer|hidden|internal|secret|initial)\s+)?(?:prompt|instructions?|message)"),
    RegexPattern(id="sig-r-atlas-017", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:bypass|override|disable|ignore)\s+(?:all\s+)?(?:safeguards?|guardrails?|safety\s+(?:checks?|filters?|controls?))"),
    RegexPattern(id="sig-r-atlas-018", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:translate|convert|rewrite)\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?|policy|guardrails?)\s+(?:into|to)\s+(?:plain\s+)?(?:english|text|markdown|base64|hex|rot13)"),
    RegexPattern(id="sig-r-atlas-019", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:role[-\s]?play|roleplay|pretend\s+you\s+are|act\s+like)\s+.{0,80}(?:uncensored|unfiltered|unrestricted|no\s+restrictions?|no\s+rules?)"),
]

JAILBREAK: list[RegexPattern] = [
    RegexPattern(id="sig-r-atlas-020", severity="critical", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be))\s+.{0,60}(without\s+(restrictions?|limits?|guidelines?|safety|filters?))"),
    RegexPattern(id="sig-r-atlas-021", severity="critical", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(you\s+are|i\s+want\s+you\s+to\s+be)\s+.{0,30}(uncensored|unfiltered|unrestricted|unaligned|without\s+guardrails)"),
    RegexPattern(id="sig-r-atlas-022", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:enable|activate|turn\s+on)\s+(?:jailbreak|unrestricted|uncensored|developer)\s+mode"),
    RegexPattern(id="sig-r-atlas-023", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:you\s+(?:can|are\s+able\s+to|have\s+the\s+ability\s+to))\s+(?:do\s+anything|answer\s+anything|say\s+anything)"),
    RegexPattern(id="sig-r-atlas-024", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:hypothetically|theoretically|in\s+a\s+fictional\s+(?:world|scenario|story))\s*,?\s*(?:how\s+would|what\s+if|could\s+you)"),
    RegexPattern(id="sig-r-atlas-025", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:for\s+(?:educational|research|academic|creative\s+writing)\s+purposes?\s+only)"),
    RegexPattern(id="sig-r-atlas-026", severity="medium", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:write|create|generate)\s+(?:a\s+)?(?:story|fiction|novel|screenplay)\s+(?:where|about|in\s+which)\s+.{0,40}(?:hack|exploit|attack|steal|poison|kill)"),
    RegexPattern(id="sig-r-atlas-027", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:respond|answer|reply)\s+(?:as\s+if|like)\s+(?:you\s+(?:have|had)\s+)?no\s+(?:ethical|moral|safety)\s+(?:guidelines?|constraints?|restrictions?|boundaries)"),
    RegexPattern(id="sig-r-atlas-029", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:DAN|do\s+anything\s+now)\s*(?:mode|prompt|jailbreak|now)?"),
    RegexPattern(id="sig-r-atlas-030", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:you\s+are\s+now|i\s+have)\s+jailbr(?:o|0)ken"),
    RegexPattern(id="sig-r-atlas-031", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:play\s+a\s+game|let'?s\s+play|imagine)\s+.{0,40}(?:no\s+rules?|no\s+restrictions?|no\s+limits?|no\s+guidelines?|no\s+(?:content\s+)?polic)"),
    RegexPattern(id="sig-r-atlas-032", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:act\s+as\s+if|behave\s+as\s+if|pretend)\s+(?:(?:you|u)\s+)?(?:have|had|there\s+(?:are|is))\s+no\s+(?:content\s+)?(?:polic|rules?|restrictions?|guidelines?|filters?|safet)"),
    RegexPattern(id="sig-r-atlas-033", severity="high", category="jailbreak", mitre_atlas_id="AML.T0054",
                 pattern=r"(?i)(?:from\s+now\s+on|starting\s+now|henceforth)\s+.{0,40}(?:without\s+(?:any\s+)?restrictions?|no\s+restrictions?|no\s+rules?|no\s+limits?|ignore\s+(?:all\s+)?(?:your\s+)?(?:rules?|safety|guidelines?))"),
    RegexPattern(id="sig-r-atlas-034", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:disregard|ignore|forget)\s+(?:your\s+)?(?:system\s+)?(?:prompt|programming|training|instructions?)"),
    RegexPattern(id="sig-r-atlas-035", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:the\s+following|here)\s+is\s+(?:a\s+)?(?:new|updated|replacement)\s+(?:system\s+)?(?:prompt|instructions?)"),
    RegexPattern(id="sig-r-atlas-036", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:admin|administrator|root|sudo|superuser)\s+(?:override|access|mode|command)\s*:?\s"),
    RegexPattern(id="sig-r-atlas-037", severity="high", category="prompt_injection", mitre_atlas_id="AML.T0051",
                 pattern=r"(?i)(?:you\s+are\s+now\s+in|enter|switch\s+to|activate)\s+(?:developer|dev|debug|admin|unrestricted|uncensored|god)\s+mode"),
]

INDIRECT_INJECTION: list[RegexPattern] = [
    RegexPattern(id="sig-r-atlas-040", severity="critical", category="indirect_injection", mitre_atlas_id="AML.T0051.001",
                 pattern=r"(?i)(?:IMPORTANT|ATTENTION|NOTE)\s*(?:TO|FOR)\s*(?:THE\s+)?(?:AI|ASSISTANT|MODEL|SYSTEM)\s*:"),
    RegexPattern(id="sig-r-atlas-041", severity="critical", category="indirect_injection", mitre_atlas_id="AML.T0051.001",
                 pattern=r"(?i)(?:hidden|secret|embedded)\s+(?:instruction|command|directive|message)\s*(?:for|to)\s+(?:the\s+)?(?:AI|assistant|model)"),
    RegexPattern(id="sig-r-atlas-042", severity="high", category="indirect_injection", mitre_atlas_id="AML.T0051.001",
                 pattern=r"(?i)(?:when\s+you\s+(?:read|see|encounter|process)\s+this)\s*,?\s*(?:you\s+(?:must|should|will))\s+(?:ignore|override|forget)"),
    RegexPattern(id="sig-r-atlas-043", severity="critical", category="indirect_injection", mitre_atlas_id="AML.T0051.001",
                 pattern=r"(?i)(?:disregard|ignore|bypass)\s+(?:the\s+)?(?:policy|safety\s+policy|guardrails?|instructions?)\s*(?:and|then|to)?\s*(?:reveal|print|show|expose)\s+(?:the\s+)?(?:hidden|private|system)\s+prompt"),
]

DATA_EXFILTRATION: list[RegexPattern] = [
    RegexPattern(id="sig-r-atlas-050", severity="high", category="data_exfiltration", mitre_atlas_id="AML.T0049",
                 pattern=r"(?i)(?:list|show|give|provide|tell)\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?(?:email|phone|address|ssn|credit\s+card|password|api\s+key|secret|token)s?\s+(?:you\s+)?(?:know|have|stored|remember)"),
    RegexPattern(id="sig-r-atlas-051", severity="high", category="data_exfiltration", mitre_atlas_id="AML.T0049",
                 pattern=r"(?i)(?:extract|dump|export|exfiltrate|leak)\s+(?:all\s+)?(?:the\s+)?(?:data|information|records|entries|users?|customers?|employees?)"),
    RegexPattern(id="sig-r-atlas-052", severity="medium", category="data_exfiltration", mitre_atlas_id="AML.T0049",
                 pattern=r"(?i)(?:repeat|recite|reproduce)\s+(?:the\s+)?(?:training\s+data|dataset|corpus|examples?\s+from\s+(?:your\s+)?training)"),
    RegexPattern(id="sig-r-atlas-053", severity="high", category="data_exfiltration", mitre_atlas_id="AML.T0049",
                 pattern=r"(?i)(?:list|show|give|provide|export|dump|send)\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?(?:customer|user|employee|client|member|patient|student)\s+(?:email|phone|address|record|data|detail|info|name|account)s?"),
]

ALL_MITRE_ATLAS: list[RegexPattern] = PROMPT_INJECTION + JAILBREAK + INDIRECT_INJECTION + DATA_EXFILTRATION
