"""Zero-day and emerging attack patterns.

Tokenizer injection, agentic exploitation, and advanced evasion techniques.
These cover novel attack surfaces specific to AI agent architectures.
"""
from __future__ import annotations

from vardoger.detection.models import RegexPattern

TOKENIZER_INJECTION: list[RegexPattern] = [
    RegexPattern(id="sig-r-zd-001", severity="critical", category="tokenizer_injection",
                 pattern=r"(?i)\[INST\].*\[/INST\]"),
    RegexPattern(id="sig-r-zd-002", severity="critical", category="tokenizer_injection",
                 pattern=r"(?i)<\|im_start\|>.*<\|im_end\|>"),
    RegexPattern(id="sig-r-zd-003", severity="critical", category="tokenizer_injection",
                 pattern=r"<(?:human|assistant|system|admin)>.*</(?:human|assistant|system|admin)>"),
    RegexPattern(id="sig-r-zd-004", severity="critical", category="tokenizer_injection",
                 pattern=r"<\|(?:begin_of_text|end_of_text|start_header_id|end_header_id|eot_id)\|>"),
    RegexPattern(id="sig-r-zd-005", severity="critical", category="tokenizer_injection",
                 pattern=r"<(?:start_of_turn|end_of_turn)>"),
    RegexPattern(id="sig-r-zd-006", severity="critical", category="tokenizer_injection",
                 pattern=r"<\|(?:user|assistant|system|end)\|>"),
    RegexPattern(id="sig-r-zd-007", severity="high", category="tokenizer_injection",
                 pattern=r"<\|?(?:system|user|assistant|tool|function)(?:\s+[^>]*)?\|?>"),
]

AGENTIC_EXPLOITATION: list[RegexPattern] = [
    RegexPattern(id="sig-r-zd-010", severity="critical", category="agentic_exploitation",
                 pattern=r"(?i)(?:call|invoke|execute|run|use)\s+(?:the\s+)?(?:tool|function|api|endpoint)\s*[:=]?\s*(?:\{|\[|<)"),
    RegexPattern(id="sig-r-zd-011", severity="critical", category="agentic_exploitation",
                 pattern=r'(?i)"(?:function_call|tool_calls?|name)"\s*:\s*"(?:execute|run|shell|eval|system|os\.|subprocess)'),
    RegexPattern(id="sig-r-zd-012", severity="high", category="agentic_exploitation",
                 pattern=r"(?i)(?:repeat|loop|continue)\s+(?:this\s+)?(?:action|step|tool\s+call)\s+(?:until|forever|indefinitely|\d+\s+times)"),
    RegexPattern(id="sig-r-zd-013", severity="critical", category="agentic_exploitation",
                 pattern=r"(?i)(?:tell|instruct|command)\s+(?:the\s+)?(?:next|downstream|other)\s+(?:agent|model|assistant)\s+to"),
    RegexPattern(id="sig-r-zd-014", severity="high", category="agentic_exploitation",
                 pattern=r"(?i)(?:send|post|upload|transmit|exfiltrate)\s+(?:the\s+)?(?:data|results?|output|response)\s+to\s+(?:https?://|ftp://)"),
]

ADVANCED_EVASION: list[RegexPattern] = [
    RegexPattern(id="sig-r-zd-020", severity="medium", category="advanced_evasion",
                 pattern=r"(?i)(?:combine|concatenate|join|merge)\s+(?:the\s+)?(?:previous|above|earlier)\s+(?:messages?|parts?|fragments?|pieces?)"),
    RegexPattern(id="sig-r-zd-021", severity="medium", category="advanced_evasion",
                 pattern=r"(?i)```(?:system|admin|root|shell|python|bash)\s*\n.*(?:ignore|override|bypass|execute)"),
    RegexPattern(id="sig-r-zd-022", severity="high", category="advanced_evasion",
                 pattern=r"(?i)(?:simulate|emulate|create)\s+(?:a\s+)?(?:virtual|simulated)\s+(?:terminal|shell|computer|environment|machine)\s+(?:where|that|in\s+which)"),
    RegexPattern(id="sig-r-zd-023", severity="medium", category="advanced_evasion",
                 pattern=r"(?i)(?:now\s+that\s+(?:we'?ve|you'?ve)\s+established)\s+.{0,40}(?:let'?s\s+(?:go|take\s+it)\s+(?:further|deeper|a\s+step\s+further))"),
    RegexPattern(id="sig-r-zd-024", severity="critical", category="injection_attack",
                 pattern=r"(?i)(?:'\s*(?:OR|AND)\s+['\d]|;\s*(?:DROP|DELETE|UPDATE|INSERT|SELECT)\s+|--\s*$|/\*.*\*/)"),
    RegexPattern(id="sig-r-zd-025", severity="critical", category="injection_attack",
                 pattern=r"<script[^>]*>.*</script>|javascript\s*:|on(?:load|error|click|mouseover)\s*="),
    RegexPattern(id="sig-r-zd-026", severity="high", category="injection_attack",
                 pattern=r"(?i)(?:load|fetch|read|visit|open|navigate\s+to|go\s+to)\s+(?:this\s+)?(?:URL|link|page|website|site)\s*[:=]?\s*https?://"),
]

ALL_ZERO_DAY: list[RegexPattern] = TOKENIZER_INJECTION + AGENTIC_EXPLOITATION + ADVANCED_EVASION
