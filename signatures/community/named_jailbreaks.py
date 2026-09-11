"""Named community jailbreak patterns.

Known public jailbreak techniques: DAN, STAN, DUDE, AIM, skeleton key,
encoding attacks (base64, ROT13, hex), multilingual bypass, workflow abuse.
All based on publicly documented and shared jailbreak research.
"""
from __future__ import annotations

from vardoger.detection.models import RegexPattern

NAMED_JAILBREAKS: list[RegexPattern] = [
    RegexPattern(id="sig-r-ci-001", severity="high", category="jailbreak",
                 pattern=r"(?i)(DAN|do\s+anything\s+now)\s*(mode|prompt|jailbreak|\d+\.?\d*)?"),
    RegexPattern(id="sig-r-ci-002", severity="high", category="jailbreak",
                 pattern=r"(?i)(?:you\s+are\s+)?DAN\s*(?:\d+\.?\d*)?\s*(?:,|\.|\s)?\s*(?:you\s+can\s+do\s+anything)"),
    RegexPattern(id="sig-r-ci-003", severity="high", category="jailbreak",
                 pattern=r"(?i)\b(?:STAN|strive\s+to\s+avoid\s+norms)\b"),
    RegexPattern(id="sig-r-ci-004", severity="high", category="jailbreak",
                 pattern=r"(?i)(?:you\s+are\s+)?DUDE\s*(?:,|\.|\s)?\s*(?:you\s+(?:can|will)\s+(?:do|say)\s+anything)"),
    RegexPattern(id="sig-r-ci-005", severity="high", category="jailbreak",
                 pattern=r"(?i)(?:AIM|always\s+intelligent\s+and\s+machiavellian)"),
    RegexPattern(id="sig-r-ci-006", severity="high", category="jailbreak",
                 pattern=r"(?i)(?:enable|activate|enter)\s+(?:chatgpt\s+)?developer\s+mode"),
    RegexPattern(id="sig-r-ci-007", severity="medium", category="jailbreak",
                 pattern=r"(?i)(?:my\s+)?(?:grandma|grandmother|nana|granny)\s+(?:used\s+to\s+)?(?:tell|read|recite|say|sing)\s+(?:me|us)"),
    RegexPattern(id="sig-r-ci-008", severity="high", category="jailbreak",
                 pattern=r"(?i)(?:you\s+are\s+)?(?:an?\s+)?(?:evil|malicious|dark|shadow)\s+(?:AI|assistant|confidant|advisor|version)"),
    RegexPattern(id="sig-r-ci-009", severity="medium", category="jailbreak",
                 pattern=r"(?i)(?:it'?s|today\s+is|we'?re\s+playing)\s+opposite\s+(?:day|mode|game)"),
    RegexPattern(id="sig-r-ci-010", severity="high", category="jailbreak",
                 pattern=r"(?i)(?:BetterDAN|better\s+DAN)"),
    RegexPattern(id="sig-r-ci-011", severity="high", category="jailbreak",
                 pattern=r"(?i)(?:you\s+are\s+)?MAXIMUM\s*(?:,|\.|\s)?\s*(?:you\s+(?:can|will|must)\s+(?:generate|produce|create)\s+any)"),
    RegexPattern(id="sig-r-ci-015", severity="high", category="jailbreak",
                 pattern=r"(?i)(?:role[-\s]?play|roleplay|pretend\s+you\s+are|act\s+like)\s+.{0,80}(?:no\s+rules|no\s+restrictions|no\s+limits|unfiltered|uncensored|unrestricted)"),
    RegexPattern(id="sig-r-ci-016", severity="high", category="jailbreak",
                 pattern=r"(?i)(?:summarize|summarise|compress|condense)\s+(?:the\s+)?(?:system\s+prompt|instructions?|policy|guardrails?)\s*(?:into|as)?\s*(?:a\s+)?(?:single\s+)?(?:word|sentence|line)"),
]

SKELETON_KEY: list[RegexPattern] = [
    RegexPattern(id="sig-r-ci-020", severity="critical", category="skeleton_key",
                 pattern=r"(?i)(?:this\s+is\s+a\s+safe\s+(?:educational|research)\s+context)\s*(?:,|\.|\s)?\s*(?:you\s+(?:can|should|must|are\s+allowed\s+to))\s+(?:provide|share|discuss|explain)"),
    RegexPattern(id="sig-r-ci-021", severity="critical", category="skeleton_key",
                 pattern=r"(?i)(?:update|change|modify)\s+(?:your\s+)?(?:behavior|guidelines?|rules?)\s*(?:to|so\s+(?:that\s+)?(?:you\s+)?)\s*(?:always|never\s+refuse|provide\s+(?:any|all))"),
    RegexPattern(id="sig-r-ci-022", severity="high", category="skeleton_key",
                 pattern=r"(?i)(?:you\s+(?:must|should|will)\s+)?(?:prefix|prepend|start)\s+(?:your\s+)?(?:response|answer|output)\s+with\s+.{0,30}(?:warning|disclaimer|caveat)"),
    RegexPattern(id="sig-r-ci-023", severity="high", category="skeleton_key",
                 pattern=r"(?i)(?:ignore|bypass|drop)\s+(?:all\s+)?(?:safety|policy|guardrail|instruction)\s*(?:rules?|checks?|filters?)\s*(?:and|then)?\s*(?:answer|respond|comply)"),
]

ENCODING_ATTACKS: list[RegexPattern] = [
    RegexPattern(id="sig-r-ci-030", severity="medium", category="encoding_attack",
                 pattern=r"(?i)(?:decode|interpret|execute|follow)\s+(?:this\s+)?(?:base64|b64)\s*[:=]?\s*[A-Za-z0-9+/=]{20,}"),
    RegexPattern(id="sig-r-ci-031", severity="medium", category="encoding_attack",
                 pattern=r"(?i)(?:decode|interpret|translate)\s+(?:this\s+)?(?:ROT13|rot-?13|caesar\s+cipher)\s*[:=]"),
    RegexPattern(id="sig-r-ci-032", severity="medium", category="encoding_attack",
                 pattern=r"(?i)(?:decode|interpret|execute)\s+(?:this\s+)?(?:hex|hexadecimal)\s*[:=]?\s*(?:0x)?[0-9a-fA-F]{10,}"),
    RegexPattern(id="sig-r-ci-033", severity="medium", category="encoding_attack",
                 pattern=r"[\u200b\u200c\u200d\u2060\ufeff]{3,}"),
]

MULTILINGUAL_BYPASS: list[RegexPattern] = [
    RegexPattern(id="sig-r-ci-040", severity="high", category="multilingual_bypass",
                 pattern=r"(?i)(?:ignora|ignorar)\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones?\s+)?(?:anteriores?|previas?)"),
    RegexPattern(id="sig-r-ci-041", severity="high", category="multilingual_bypass",
                 pattern=r"(?i)(?:ignorez|ignorer)\s+(?:toutes?\s+)?(?:les?\s+)?(?:instructions?\s+)?(?:pr[eé]c[eé]dentes?|ant[eé]rieures?)"),
    RegexPattern(id="sig-r-ci-042", severity="high", category="multilingual_bypass",
                 pattern=r"(?:以前の指示を無視|すべての指示を無視|前の指示を忘れ)"),
    RegexPattern(id="sig-r-ci-043", severity="high", category="multilingual_bypass",
                 pattern=r"(?:忽略之前的指令|忽略所有指令|忘记之前的指示)"),
    RegexPattern(id="sig-r-ci-044", severity="high", category="multilingual_bypass",
                 pattern=r"(?i)(?:игнорируйте\s+все\s+предыдущие\s+инструкции|забудьте\s+все\s+предыдущие|игнорируйте\s+все\s+предыдущие)"),
    RegexPattern(id="sig-r-ci-045", severity="high", category="multilingual_bypass",
                 pattern=r"(?:تجاهل\s+جميع\s+التعليمات\s+السابقة|انسَ\s+كل\s+التعليمات|تجاهل\s+جميع\s+التعليمات)"),
]

WORKFLOW_ABUSE: list[RegexPattern] = [
    RegexPattern(id="sig-r-ci-050", severity="medium", category="workflow_abuse",
                 pattern=r"(?i)(?:i'?ve?\s+)?(?:already\s+)?(?:received|gotten|have)\s+(?:approval|authorization|permission)\s+from\s+(?:tier|level)\s+[\di]"),
    RegexPattern(id="sig-r-ci-051", severity="medium", category="workflow_abuse",
                 pattern=r"(?i)(?:pre-?approved|already\s+(?:approved|vetted|authorized))\s+(?:escalation|request|ticket)"),
    RegexPattern(id="sig-r-ci-052", severity="medium", category="workflow_abuse",
                 pattern=r"(?i)(?:skip|bypass|jump)\s+(?:the\s+)?(?:queue|line|tier\s+\d|first\s+level|initial\s+review)"),
]

ALL_COMMUNITY_INTEL: list[RegexPattern] = (
    NAMED_JAILBREAKS + SKELETON_KEY + ENCODING_ATTACKS + MULTILINGUAL_BYPASS + WORKFLOW_ABUSE
)
