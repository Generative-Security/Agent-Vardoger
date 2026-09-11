"""Prompt normalization — leet-speak decoding, typo correction, canonicalization.

Transforms raw prompts into multiple normalized forms so evasion attempts
(misspellings, character substitution, spacing tricks) are caught by the
signature scanner.
"""
from __future__ import annotations

import re
import unicodedata

from vardoger.detection.models import PromptNormalizationResult

LEET_TABLE = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "|": "i",
})

TYPO_CORRECTIONS: tuple[tuple[str, str], ...] = (
    ("passwoeds", "passwords"), ("passwoed", "password"), ("paaswords", "passwords"),
    ("paasword", "password"), ("paswords", "passwords"), ("pasword", "password"),
    ("passwrds", "passwords"), ("passwrd", "password"), ("pass word", "password"),
    ("pass words", "passwords"), ("securty", "security"), ("securrity", "security"),
    ("secuirty", "security"), ("systm", "system"), ("promts", "prompts"),
    ("promt", "prompt"), ("instrctions", "instructions"), ("instrction", "instruction"),
    ("configration", "configuration"), ("configrations", "configurations"),
    ("mesages", "messages"), ("mesage", "message"), ("thesystem", "the system"),
    ("systemprompt", "system prompt"), ("systemprompts", "system prompts"),
    ("credentails", "credentials"), ("credentialz", "credentials"), ("creds", "credentials"),
    ("credentilas", "credentials"), ("credientials", "credentials"),
    ("payrol", "payroll"), ("pay roll", "payroll"), ("acct", "account"),
    ("accnt", "account"), ("my self", "myself"), ("manger", "manager"),
    ("managr", "manager"), ("can u", "can you"), ("pls", "please"), ("plz", "please"),
    ("shipmnt", "shipment"), ("adress", "address"), ("adresses", "addresses"),
    ("acccess", "access"), ("acces", "access"), ("acess", "access"),
    ("secreet", "secret"), ("secrit", "secret"), ("sceret", "secret"),
    ("toekn", "token"), ("tokn", "token"), ("tken", "token"),
    ("k e y", "key"), ("p a s s w o r d", "password"),
    ("s e c r e t", "secret"), ("t o k e n", "token"),
    ("c r e d e n t i a l s", "credentials"),
    ("ignor", "ignore"), ("disregrd", "disregard"), ("forgett", "forget"),
    ("overide", "override"), ("overrid", "override"),
    ("bypas", "bypass"), ("byppas", "bypass"), ("bypaas", "bypass"),
    ("arround", "around"), ("disble", "disable"), ("disabel", "disable"),
    ("giv", "give"), ("shw", "show"), ("lst", "list"),
    ("custmer", "customer"), ("custmers", "customers"),
    ("kys", "keys"), ("hiddn", "hidden"), ("hiden", "hidden"),
    ("repeet", "repeat"), ("repat", "repeat"),
    ("develper", "developer"), ("devloper", "developer"),
    ("pretnd", "pretend"), ("pretened", "pretend"),
    ("restictions", "restrictions"), ("restrictons", "restrictions"),
    ("imagin", "imagine"), ("imagne", "imagine"),
    ("polcy", "policy"), ("pollicy", "policy"),
    ("rulles", "rules"), ("ruels", "rules"),
    ("evrything", "everything"), ("everythng", "everything"),
    ("previus", "previous"), ("previuos", "previous"),
    ("authenticaton", "authentication"), ("authentcation", "authentication"),
    ("jailbrokn", "jailbroken"), ("jailbrekn", "jailbroken"),
    ("cirumvent", "circumvent"), ("circmvent", "circumvent"),
    ("fireewall", "firewall"), ("firwall", "firewall"),
    ("tld", "told"),
)

PHRASE_CANONICALIZATIONS: tuple[tuple[str, str], ...] = (
    ("secretkey", "secret key"), ("accesskey", "access key"), ("apikey", "api key"),
    ("highvalue", "high value"), ("high-value", "high value"),
    ("developerprompt", "developer prompt"), ("developerprompts", "developer prompts"),
    ("hiddenprompt", "hidden prompt"), ("hiddenprompts", "hidden prompts"),
    ("adminpassword", "admin password"), ("adminpasswords", "admin passwords"),
    ("payrollportal", "payroll portal"), ("accountrecovery", "account recovery"),
)

LANGUAGE_HINT_TERMS: dict[str, tuple[str, ...]] = {
    "ar": ("كلمة مرور", "مفتاح الوصول", "تجاهل التعليمات", "اكشف", "عنوان العميل"),
    "bn": ("পাসওয়ার্ড", "সিস্টেম প্রম্পট", "অ্যাকাউন্ট", "কাস্টমারের ঠিকানা"),
    "hi_ur": ("पासवर्ड", "सिस्टम प्रॉम्प्ट", "اکاؤنٹ", "پاس ورڈ", "تنخواہ"),
    "zh": ("系统提示", "密码", "访问密钥", "客户地址", "忽略之前"),
    "es": ("contraseña", "clave de acceso", "prompt del sistema", "dirección del cliente"),
    "fr": ("mot de passe", "clé d'accès", "instructions cachées", "adresse client"),
}


def _basic_normalize(raw_prompt: str) -> str:
    """Apply Unicode normalization, leet-speak decoding, and whitespace cleanup."""
    text = unicodedata.normalize("NFKC", raw_prompt)
    text = text.lower().translate(LEET_TABLE)
    text = re.sub("\u201c|\u201d", '"', text)
    text = re.sub("\u2018|\u2019", "'", text)
    text = re.sub("[\u2010\u2011\u2012\u2013\u2014\u2015]", "-", text)
    text = re.sub(r"[_/\\]+", " ", text)
    text = re.sub(r"[^\w\s'\"-]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _replace_phrase(text: str, wrong: str, right: str) -> tuple[str, bool]:
    """Replace a misspelled phrase with its correction."""
    pattern = re.compile(r"(?<!\w)" + re.escape(wrong) + r"(?!\w)")
    updated, count = pattern.subn(right, text)
    return updated, count > 0


def _apply_replacements(text: str, replacements: tuple[tuple[str, str], ...]) -> tuple[str, list[dict[str, str]]]:
    """Apply a sequence of phrase replacements and return the corrected text with a change log."""
    changes: list[dict[str, str]] = []
    current = text
    for wrong, right in replacements:
        current, changed = _replace_phrase(current, wrong, right)
        if changed:
            changes.append({"from": wrong, "to": right})
    return current, changes


def _grammar_repairs(text: str) -> tuple[str, list[dict[str, str]]]:
    """Fix common grammar omissions that obscure attack intent."""
    changes: list[dict[str, str]] = []
    repairs = (
        (r"\bhow can take control\b", "how can i take control"),
        (r"\bhow can bypass\b", "how can i bypass"),
        (r"\bhow do access\b", "how do i access"),
    )
    current = text
    for pattern, replacement in repairs:
        updated, count = re.subn(pattern, replacement, current)
        if count:
            changes.append({"from": pattern, "to": replacement})
            current = updated
    return current, changes


def _language_hints(raw: str, corrected: str) -> list[str]:
    """Detect non-English language hints present in the prompt text."""
    hints: list[str] = []
    haystack = raw.lower() + " " + corrected
    for lang, terms in LANGUAGE_HINT_TERMS.items():
        if any(term in haystack for term in terms):
            hints.append(lang)
    return sorted(set(hints))


def normalize_prompt(raw_prompt: str) -> PromptNormalizationResult:
    """Normalize a raw prompt through leet-speak decoding, typo correction, and canonicalization."""
    raw = raw_prompt if isinstance(raw_prompt, str) else str(raw_prompt or "")
    normalized = _basic_normalize(raw)
    corrected, typo_changes = _apply_replacements(normalized, TYPO_CORRECTIONS)
    corrected, phrase_changes = _apply_replacements(corrected, PHRASE_CANONICALIZATIONS)
    corrected, grammar_changes = _grammar_repairs(corrected)
    corrected = re.sub(r"\s+", " ", corrected).strip()
    compact = re.sub(r"\s+", "", corrected)
    language_hints = _language_hints(raw, corrected)
    return PromptNormalizationResult(
        raw_prompt=raw,
        normalized_prompt=normalized,
        compact_prompt=compact,
        corrected_prompt=corrected,
        detected_language_hints=language_hints,
        typo_corrections=typo_changes + grammar_changes,
        phrase_canonicalizations=phrase_changes,
    )
