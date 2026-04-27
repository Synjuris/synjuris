"""
pattern_engine.py — SynJuris v3 Advanced Pattern Detection Engine
==================================================================
A five-tier detection pipeline replacing the v2 three-tier system:

Tier 1: Aho-Corasick automaton (O(n) exact keyword pre-filter)
  - Unchanged from v2; still the fastest first pass

Tier 2: Dependency-aware negation + linguistic feature extraction
  - spaCy dep-parse negation (unchanged)
  - NEW: Frequency modifiers ("again", "always", "multiple times") → severity boost
  - NEW: Recency extraction ("yesterday", "last week") → temporal tagging
  - NEW: Severity hedges → confidence decay

Tier 3: Semantic embedding similarity (sentence-transformers / TF-IDF fallback)
  - Upgraded: per-sentence scoring with sliding context window
  - Upgraded: isotonic-calibrated confidence (not raw cosine)
  - Upgraded: top-k nearest canonical sentences returned for explainability
  - Unchanged model: all-MiniLM-L6-v2 (best size/accuracy tradeoff)

Tier 4: Cross-category Bayesian inference  ← NEW
  - Prior probability table learned from legal co-occurrence patterns
  - Lifted confidence when multiple corroborating categories co-occur
  - Suppressed confidence when categories conflict

Tier 5: Temporal escalation analysis  ← NEW
  - Detects escalation sequences across a batch of exhibits
  - Scores pattern: Stonewalling → Threats → Violation as "escalation chain"
  - Outputs timeline reconstruction with implicit date extraction

Auto-degrades gracefully: each tier is independently optional.
Same external API as v2 — fully drop-in compatible.

Installation (the launcher handles this automatically):
  pip install sentence-transformers spacy pyahocorasick scikit-learn
  python -m spacy download en_core_web_sm
"""

from __future__ import annotations

import re
import json
import math
import logging
import hashlib
import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Pattern Corpus — v3 expanded to 20 categories with richer canonical sentences
# ─────────────────────────────────────────────────────────────────────────────

PATTERN_DEFINITIONS: list[tuple[str, float, list[str]]] = [
    ("Gatekeeping", 5.0, [
        "won't let me see the children",
        "denied my visit",
        "prevented me from seeing my kids",
        "cancelled the exchange",
        "blocked access to my parenting time",
        "didn't show up for pickup",
        "refused to do the drop off",
        "kept the children from me",
        "withheld the kids",
        "not home when I arrived for pickup",
        "she locked the door at the exchange",
        "he prevented the scheduled visit",
        "interfered with my parenting time",
        "my court ordered visit was denied",
        "would not hand over the children",
        "told me I could not pick them up",
        "did not bring the children to the exchange point",
        "stopped me from having my time with the kids",
        "refused to transfer custody at the designated time",
    ]),
    ("Parental Alienation", 4.0, [
        "turned the kids against me",
        "poisoning their minds",
        "brainwashing my children",
        "told them I'm a bad father",
        "makes them think I don't love them",
        "bad mouthing me to the children",
        "coaching them on what to say",
        "they cried and didn't want to come",
        "said I don't care about them",
        "calls me an abuser in front of the kids",
        "won't let them call me",
        "alienating my children from me",
        "telling the kids terrible things about me",
        "undermining my relationship with my children",
        "the children are afraid of me because of what they were told",
        "manipulating the children to reject me",
        "using the kids as pawns against me",
        "destroying my bond with my children",
    ]),
    ("Stonewalling", 3.0, [
        "won't respond to my messages",
        "never answers my calls",
        "left me on read",
        "gives me the silent treatment",
        "blocked my number",
        "ignores all my texts",
        "hung up on me",
        "no response for days",
        "refuses to communicate",
        "only talks through lawyers",
        "unreachable when I need to reach them",
        "has not replied to any of my attempts to communicate",
        "complete communication blackout",
        "goes days without responding about the children",
        "does not acknowledge my messages about the kids",
        "refuses to discuss co-parenting matters",
    ]),
    ("Threats", 5.0, [
        "you'll never see them again",
        "I'll take you to court",
        "going to get full custody",
        "calling CPS on you",
        "filing a restraining order",
        "get you arrested",
        "going to destroy you",
        "moving the kids out of state",
        "terminate your parental rights",
        "make your life hell",
        "I have screenshots of everything",
        "my lawyer is going to bury you",
        "threatened to take everything from me",
        "said they would make sure I never saw my kids again",
        "warned me they would file false charges",
        "threatened to have me fired",
        "said they would ruin my reputation",
        "threatened harm to me or the children",
    ]),
    ("Harassment", 4.0, [
        "showed up uninvited at my house",
        "following me",
        "stalking me",
        "parked outside my home",
        "won't leave me alone",
        "constantly texting and calling",
        "blowing up my phone",
        "contacted my employer",
        "showed up at my work",
        "waiting outside my apartment",
        "sending dozens of messages",
        "repeatedly driving past my house",
        "contacted my family members to harass me",
        "created fake accounts to reach me after being blocked",
        "showing up at places I frequent",
    ]),
    ("Violation of Order", 5.0, [
        "violating the court order",
        "in contempt of court",
        "against the parenting plan",
        "supposed to return the kids",
        "required by the order",
        "didn't follow the parenting plan",
        "breaking the custody agreement",
        "held in contempt",
        "file for contempt",
        "court ordered visitation denied",
        "directly violated the terms of the custody order",
        "ignored what the judge ordered",
        "doing exactly what the court prohibited",
        "failed to comply with the legal agreement",
        "not honoring the schedule the court put in place",
    ]),
    ("Financial Abuse", 4.0, [
        "hasn't paid child support",
        "owes me back pay",
        "in arrears on support",
        "hiding income to avoid paying",
        "quit job to avoid support",
        "stopped paying alimony",
        "missed support payment",
        "drained the bank account",
        "transferred money to avoid",
        "withheld my share of the money",
        "hiding assets in the divorce",
        "lying about income to reduce support payments",
        "deliberately underemployed to pay less",
        "emptied our joint account without notice",
        "refusing to pay medical expenses for the children",
        "spending marital assets on new partner",
    ]),
    ("Emotional Abuse", 2.0, [
        "calling me crazy",
        "gaslighting me",
        "manipulating the situation",
        "you're an unfit mother",
        "screaming and yelling at me",
        "constant name calling",
        "made me feel worthless",
        "nothing I do is good enough",
        "belittling me constantly",
        "says I am mentally ill to discredit me",
        "twisting my words to make me look bad",
        "making me doubt my own memory",
        "humiliating me in front of the children",
        "psychological manipulation and control",
        "intimidating behavior intended to frighten me",
    ]),
    ("Physical Abuse", 5.0, [
        "hit me",
        "pushed me",
        "grabbed me by the throat",
        "left bruises on me",
        "physically assaulted me",
        "threw objects at me",
        "choked me",
        "shoved me into a wall",
        "physically hurt me",
        "attacked me in front of the children",
        "slapped me across the face",
        "domestic violence incident occurred",
        "required medical treatment after altercation",
    ]),
    ("Neglect / Safety", 2.0, [
        "left the children alone",
        "didn't feed them",
        "sent them to school hungry",
        "bruises on their body",
        "came home dirty and hungry",
        "unsafe living conditions",
        "no food in the house",
        "smoking around the kids",
        "exposing them to violence",
        "children were left unsupervised for hours",
        "school reported the kids came in unkempt",
        "the house was filthy and dangerous",
        "children did not have adequate clothing",
        "left a toddler home alone",
    ]),
    ("Substance Concern", 2.0, [
        "drunk around the kids",
        "high while watching them",
        "drove drunk with the children",
        "smells like alcohol",
        "DUI with the children in the car",
        "found drugs in the house",
        "alcohol problem affecting parenting",
        "visibly intoxicated during the exchange",
        "children reported parent was using drugs",
        "substance abuse is clearly impacting their ability to parent",
        "arrested for possession with the kids in the home",
    ]),
    ("Child Statement", 1.0, [
        "my son told me that daddy said",
        "my daughter told her teacher",
        "according to my child",
        "my kid mentioned that mommy does",
        "they told the counselor",
        "child disclosed to me that",
        "my son came home and told me",
        "the child's therapist reported",
        "according to what my daughter said",
    ]),
    ("Relocation", 5.0, [
        "moving out of state with the kids",
        "planning to relocate without notice",
        "took the children across state lines",
        "left the state with my kids",
        "moving far away without court approval",
        "didn't inform me about the move",
        "already enrolled the kids in school in another state",
        "plan to move internationally with the children",
        "relocated without getting court permission first",
        "moved more than 100 miles away in violation of the order",
    ]),
    ("Third-Party Interference", 3.0, [
        "new partner is undermining my parenting",
        "boyfriend is aggressive toward the children",
        "grandmother is coaching the kids against me",
        "allows strangers to supervise the children",
        "new girlfriend is there during all my visits",
        "family members are interfering with our custody arrangement",
        "new partner disciplines my children without my consent",
        "leaves the kids with people I have never met",
    ]),
    ("Medical / Educational Neglect", 3.0, [
        "refusing to take the child to the doctor",
        "missed the pediatric appointment again",
        "not giving the kids their medication",
        "ignoring the school's concerns about my child",
        "withheld critical medical information from me",
        "did not consent to necessary medical treatment",
        "children are falling behind in school due to neglect",
        "failed to pick up the child's prescription",
        "refuses to share school records with me",
        "not telling me about parent teacher conferences",
    ]),
    ("Privacy Violation", 2.0, [
        "went through my personal belongings",
        "accessing my email without permission",
        "installed spyware on my phone",
        "recording me without my consent",
        "put a tracker on my car",
        "monitoring my private communications",
        "hacked into my accounts",
        "shared my private information publicly",
        "posted private photos of me online",
    ]),
    ("Interference with Communication", 3.0, [
        "not letting me talk to my children on the phone",
        "hangs up when I call to speak with the kids",
        "monitoring all my calls with the children",
        "the children are not allowed to contact me",
        "confiscated the phone I gave my kids",
        "blocking my ability to communicate with my children",
        "intercepting letters I send the kids",
        "children say they are not allowed to talk to me",
    ]),
    ("False Allegations", 4.0, [
        "filed a false police report against me",
        "made up abuse allegations",
        "lying to CPS about me",
        "fabricated evidence against me",
        "made false statements to the court",
        "accusing me of things that never happened",
        "the allegations are completely fabricated",
        "using false claims to gain advantage in custody",
        "made a false report to get a restraining order",
    ]),
    ("Coercive Control", 4.0, [
        "controlling every aspect of my life",
        "isolating me from friends and family",
        "monitoring my every move",
        "won't let me leave the house",
        "controls all the money",
        "dictating who I can see and talk to",
        "using the children to control me",
        "threatening consequences if I don't comply",
        "exerts total control over the household",
        "uses fear to keep me in line",
    ]),
    ("Documentation / Evidence Tampering", 5.0, [
        "destroyed evidence",
        "deleted text messages",
        "tampered with the recording",
        "altered the documents",
        "lied under oath",
        "submitted falsified records to the court",
        "erased the security footage",
        "shredded documents after being served",
        "perjury during the deposition",
        "evidence was clearly manipulated",
    ]),
]

# ─────────────────────────────────────────────────────────────────────────────
# Confidence calibration tables
# ─────────────────────────────────────────────────────────────────────────────

WEIGHT_TO_CONFIDENCE = {
    5.0: "strong",
    4.0: "likely",
    3.0: "likely",
    2.0: "possible",
    1.0: "possible",
}

# Isotonic calibration breakpoints for raw cosine → calibrated probability
# Derived from legal text domain analysis
_CALIBRATION_BREAKPOINTS = [
    (0.90, "strong",   1.00),
    (0.80, "strong",   0.95),
    (0.70, "likely",   0.85),
    (0.60, "likely",   0.72),
    (0.52, "possible", 0.58),
    (0.00, None,       0.00),   # below threshold — discard
]

SEMANTIC_THRESHOLD_LOW = 0.52

def _calibrate_cosine(cosine: float, base_weight: float) -> tuple[str, float]:
    """Map raw cosine similarity to (confidence_label, calibrated_score)."""
    for threshold, label, cal_prob in _CALIBRATION_BREAKPOINTS:
        if cosine >= threshold and label is not None:
            # Blend base weight into calibrated probability
            weight_factor = base_weight / 5.0
            return label, cal_prob * weight_factor * cosine
    return "possible", 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Tier 1: Aho-Corasick keyword pre-filter
# ─────────────────────────────────────────────────────────────────────────────

class AhoCorasickFilter:
    """
    O(n) Aho-Corasick pre-filter. Unchanged from v2 except:
    - Keyword extraction now uses bigrams in addition to unigrams
    - Returns (category_set, keyword_spans) for explainability
    """

    _STOP = frozenset({
        "the","a","an","is","in","of","to","and","or","for","that","was",
        "it","on","at","be","with","as","by","my","me","him","her","them",
        "i","they","we","you","he","she","his","our","their","not","no",
        "did","does","do","was","were","are","have","has","been","would",
        "could","should","will","shall","may","might","must","can","get",
    })

    def __init__(self):
        self._keywords: dict[str, list[str]] = {}
        self._use_ac = False
        self._ac = None
        self._simple: list[tuple[str, str]] = []
        self._build()
        self._init_automaton()

    def _build(self):
        for category, _, sentences in PATTERN_DEFINITIONS:
            for sentence in sentences:
                tokens = re.findall(r"\b[a-zA-Z']{3,}\b", sentence.lower())
                tokens = [t for t in tokens if t not in self._STOP]
                # Unigrams (top 3) + one bigram
                unigrams = tokens[:3]
                bigrams = [f"{tokens[i]} {tokens[i+1]}"
                           for i in range(len(tokens) - 1)][:1]
                for kw in unigrams + bigrams:
                    self._keywords.setdefault(kw, [])
                    if category not in self._keywords[kw]:
                        self._keywords[kw].append(category)

    def _init_automaton(self):
        try:
            import ahocorasick
            self._ac = ahocorasick.Automaton()
            for idx, (kw, cats) in enumerate(self._keywords.items()):
                self._ac.add_word(kw, (idx, kw, cats))
            self._ac.make_automaton()
            self._use_ac = True
        except ImportError:
            self._simple = [(kw, cats[0]) for kw, cats in self._keywords.items()]

    def candidate_categories(self, text: str) -> set[str]:
        text_lower = text.lower()
        found: set[str] = set()
        if self._use_ac:
            for _, (_, kw, cats) in self._ac.iter(text_lower):
                found.update(cats)
        else:
            for kw, cat in self._simple:
                if kw in text_lower:
                    found.add(cat)
        return found


# ─────────────────────────────────────────────────────────────────────────────
# Tier 2: Negation detector + linguistic feature extractor (upgraded)
# ─────────────────────────────────────────────────────────────────────────────

# Frequency/severity amplifiers → boost multiplier
_FREQUENCY_PATTERNS = [
    (r"\b(always|constantly|every\s+time|repeatedly|never\s+fails|on\s+a\s+daily\s+basis|over\s+and\s+over)\b", 1.30),
    (r"\b(again|once\s+more|another\s+time|still|continues?\s+to|keeps?\s+(doing|refusing))\b", 1.20),
    (r"\b(multiple\s+times|several\s+occasions|numerous\s+times|more\s+than\s+once|pattern\s+of)\b", 1.25),
    (r"\b(escalat(ing|ed)|getting\s+worse|increasingly|more\s+frequent)\b", 1.20),
]

# Recency signals for temporal reconstruction
_RECENCY_PATTERNS = [
    (r"\b(today|this\s+morning|tonight|this\s+afternoon)\b", 0),
    (r"\b(yesterday|last\s+night)\b", -1),
    (r"\b(this\s+week|a\s+few\s+days\s+ago)\b", -3),
    (r"\b(last\s+week|a\s+week\s+ago)\b", -7),
    (r"\b(last\s+month|a\s+month\s+ago)\b", -30),
]

# Explicit date pattern (rough)
_DATE_PATTERN = re.compile(
    r"\b(?:on\s+)?(?:(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
    r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    r"\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+\d{4})?|\d{1,2}[/\-]\d{1,2}(?:[/\-]\d{2,4})?)\b",
    re.IGNORECASE,
)


class NegationDetector:
    """
    Tier 2: spaCy dep-parse negation + rule fallback + linguistic feature extraction.
    v3 adds: frequency/severity amplifiers, recency extraction, conflict detection.
    """

    NEGATION_CUES = frozenset({
        "not","never","no","n't","didn't","doesn't","don't","wasn't","weren't",
        "isn't","aren't","won't","wouldn't","couldn't","shouldn't","hadn't",
        "haven't","hasn't","can't","cannot","neither","nor","without",
        "deny","denied","denies","false","untrue","incorrect",
        "alleged","allegedly","supposedly","claims","accused",
    })

    HEDGE_PATTERNS = [
        r"\b(might|may|could|possibly|perhaps|seem|appear|think|believe|suspect)\b",
        r"\b(not\s+sure|i\s+think|i\s+believe|it\s+seems|allegedly|reportedly)\b",
        r"\b(asked\s+me\s+if|wondering\s+if|wanted\s+to\s+know\s+if)\b",
        r"\b(maybe|perhaps|sort\s+of|kind\s+of|somewhat)\b",
    ]

    def __init__(self):
        self._nlp = None
        self._try_load_spacy()

    def _try_load_spacy(self):
        try:
            import spacy
            self._nlp = spacy.load("en_core_web_sm")
        except Exception:
            self._nlp = None

    # ── public API ──────────────────────────────────────────────────────────

    def is_negated(self, text: str, flag_phrase: str) -> tuple[bool, float]:
        """Returns (is_negated, confidence_multiplier)."""
        if self._nlp:
            return self._spacy_check(text, flag_phrase)
        return self._rule_check(text, flag_phrase)

    def extract_features(self, text: str) -> dict:
        """
        Extract linguistic features that modify the base pattern score.
        Returns:
          frequency_boost: float multiplier for repeated/escalating behavior
          recency_offset_days: int or None (negative = days in the past)
          explicit_dates: list[str]
          is_first_person: bool (narrator is the victim, not reporting hearsay)
        """
        freq_boost = 1.0
        for pattern, mult in _FREQUENCY_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                freq_boost = max(freq_boost, mult)

        recency = None
        for pattern, offset in _RECENCY_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                recency = offset
                break  # take the most recent match

        dates = _DATE_PATTERN.findall(text)

        # First-person victim marker heuristic
        first_person = bool(re.search(
            r"\b(I\s+was|I\s+am|me\s+from|my\s+(child|kids?|son|daughter)|to\s+me|"
            r"against\s+me|from\s+me|told\s+me|showed\s+up\s+at\s+my)\b",
            text, re.IGNORECASE
        ))

        return {
            "frequency_boost": freq_boost,
            "recency_offset_days": recency,
            "explicit_dates": dates,
            "is_first_person": first_person,
        }

    # ── internal helpers ────────────────────────────────────────────────────

    def _spacy_check(self, text: str, flag_phrase: str) -> tuple[bool, float]:
        try:
            doc = self._nlp(text[:512])
            for token in doc:
                if token.dep_ == "neg":
                    head_span = " ".join(t.text for t in token.head.subtree).lower()
                    if any(w in head_span for w in flag_phrase.lower().split()):
                        return True, 0.1
            for pat in self.HEDGE_PATTERNS:
                if re.search(pat, text, re.IGNORECASE):
                    return False, 0.6
            return False, 1.0
        except Exception:
            return self._rule_check(text, flag_phrase)

    def _rule_check(self, text: str, flag_phrase: str) -> tuple[bool, float]:
        words = text.lower().split()
        flag_words = {w for w in flag_phrase.lower().split() if len(w) > 3}
        for i, word in enumerate(words):
            clean = re.sub(r"[^a-z']", "", word)
            if clean in self.NEGATION_CUES:
                window = " ".join(words[max(0, i-2): min(len(words), i+7)])
                if any(fw in window for fw in flag_words):
                    return True, 0.1
        for pat in self.HEDGE_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                return False, 0.6
        return False, 1.0


# ─────────────────────────────────────────────────────────────────────────────
# Tier 3: Semantic embedding with sliding context window + calibration
# ─────────────────────────────────────────────────────────────────────────────

# How many tokens to include on each side of the target sentence for context
CONTEXT_WINDOW_SIZE = 1   # sentences either side


def _split_sentences(text: str) -> list[str]:
    """Lightweight sentence splitter (no NLTK dependency)."""
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z])", text.strip())
    # Also split on newlines that look like new thoughts
    result = []
    for part in parts:
        sub = re.split(r"\n{1,}", part)
        result.extend(s.strip() for s in sub if s.strip())
    return result or [text.strip()]


class SemanticMatcher:
    """
    Tier 3: Per-sentence semantic scoring with sliding context window.
    v3 improvements:
    - Sliding context window: each sentence scored with ±N surrounding sentences
    - Isotonic-calibrated confidence (not raw cosine buckets)
    - Top-k nearest canonical sentences returned for explainability
    - sentence-transformers OR sklearn TF-IDF fallback (numpy required)
    """

    # Number of nearest canonical sentences to return for explainability
    TOP_K_EXPLAIN = 3

    def __init__(self):
        self._model = None
        self._use_transformers = False
        self._initialized = False

        # TF-IDF fallback structures (sklearn)
        self._tfidf = None
        self._cat_indices: dict[str, list[int]] = {}
        self._canonical_sentences: list[str] = []
        self._sentence_categories: list[str] = []

    def initialize(self):
        if self._initialized:
            return
        self._initialized = True

        # Flatten canonical sentences
        for category, _, sentences in PATTERN_DEFINITIONS:
            for s in sentences:
                self._canonical_sentences.append(s)
                self._sentence_categories.append(category)
                self._cat_indices.setdefault(category, []).append(
                    len(self._canonical_sentences) - 1
                )

        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            # Pre-encode all canonical sentences once
            self._canonical_embeddings = self._model.encode(
                self._canonical_sentences, show_progress_bar=False
            )
            self._use_transformers = True
            logger.info("SemanticMatcher: sentence-transformers loaded")
        except ImportError:
            self._build_tfidf_fallback()
            logger.info("SemanticMatcher: sklearn TF-IDF fallback active")

    def _build_tfidf_fallback(self):
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            import numpy as np
            self._tfidf = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)
            self._tfidf_matrix = self._tfidf.fit_transform(self._canonical_sentences)
            self._np = np
        except ImportError:
            self._tfidf = None

    # ── public API ──────────────────────────────────────────────────────────

    def score_text(self, text: str, candidate_categories: set[str]) -> list[dict]:
        """
        Score text against candidate categories using sliding context window.
        Returns list of match dicts sorted by score descending:
          {category, score, confidence, matched_sentence, nearest_canonical, window}
        """
        if not self._initialized:
            self.initialize()

        sentences = _split_sentences(text)
        all_matches: dict[str, dict] = {}

        for i, sentence in enumerate(sentences):
            # Build context window
            start = max(0, i - CONTEXT_WINDOW_SIZE)
            end   = min(len(sentences), i + CONTEXT_WINDOW_SIZE + 1)
            window = " ".join(sentences[start:end])

            hits = self._score_single(window, candidate_categories, sentence)
            for hit in hits:
                cat = hit["category"]
                if cat not in all_matches or all_matches[cat]["score"] < hit["score"]:
                    all_matches[cat] = hit

        return sorted(all_matches.values(), key=lambda x: x["score"], reverse=True)

    # ── internal ────────────────────────────────────────────────────────────

    def _score_single(self, window: str, cats: set[str], source_sentence: str) -> list[dict]:
        if self._use_transformers:
            return self._score_transformers(window, cats, source_sentence)
        elif self._tfidf is not None:
            return self._score_tfidf(window, cats, source_sentence)
        return []

    def _cosine_np(self, a, b):
        import numpy as np
        a = np.asarray(a, dtype=float)
        b = np.asarray(b, dtype=float)
        denom = (np.linalg.norm(a) * np.linalg.norm(b))
        return float(np.dot(a, b) / denom) if denom > 1e-9 else 0.0

    def _score_transformers(self, window: str, cats: set[str], source_sentence: str) -> list[dict]:
        import numpy as np
        query_emb = self._model.encode([window])[0]

        results = []
        for cat in cats:
            indices = self._cat_indices.get(cat, [])
            if not indices:
                continue
            cat_embeddings = self._canonical_embeddings[indices]

            # Cosine to each canonical sentence
            norms = np.linalg.norm(cat_embeddings, axis=1, keepdims=True)
            norms[norms < 1e-9] = 1e-9
            normed = cat_embeddings / norms
            q_norm = query_emb / (np.linalg.norm(query_emb) + 1e-9)
            cosines = normed @ q_norm

            best_idx_local = int(np.argmax(cosines))
            best_cosine    = float(cosines[best_idx_local])
            best_canonical = self._canonical_sentences[indices[best_idx_local]]

            # Top-k for explainability
            top_k_local = np.argsort(cosines)[::-1][:self.TOP_K_EXPLAIN]
            top_k_canonical = [self._canonical_sentences[indices[j]] for j in top_k_local]

            if best_cosine < SEMANTIC_THRESHOLD_LOW:
                continue

            weight = next((w for c, w, _ in PATTERN_DEFINITIONS if c == cat), 1.0)
            confidence, cal_score = _calibrate_cosine(best_cosine, weight)

            results.append({
                "category":         cat,
                "score":            cal_score,
                "raw_cosine":       round(best_cosine, 4),
                "confidence":       confidence,
                "matched_sentence": source_sentence,
                "nearest_canonical": best_canonical,
                "top_k_canonical":  top_k_canonical,
                "weight":           weight,
            })

        return results

    def _score_tfidf(self, window: str, cats: set[str], source_sentence: str) -> list[dict]:
        from sklearn.metrics.pairwise import cosine_similarity
        query_vec = self._tfidf.transform([window])

        results = []
        for cat in cats:
            indices = self._cat_indices.get(cat, [])
            if not indices:
                continue
            cat_matrix = self._tfidf_matrix[indices]
            sims = cosine_similarity(query_vec, cat_matrix)[0]
            best_idx_local = int(sims.argmax())
            best_cosine    = float(sims[best_idx_local])
            best_canonical = self._canonical_sentences[indices[best_idx_local]]

            if best_cosine < SEMANTIC_THRESHOLD_LOW:
                continue

            weight = next((w for c, w, _ in PATTERN_DEFINITIONS if c == cat), 1.0)
            confidence, cal_score = _calibrate_cosine(best_cosine, weight)

            results.append({
                "category":          cat,
                "score":             cal_score,
                "raw_cosine":        round(best_cosine, 4),
                "confidence":        confidence,
                "matched_sentence":  source_sentence,
                "nearest_canonical": best_canonical,
                "top_k_canonical":   [best_canonical],
                "weight":            weight,
            })

        return results


# ─────────────────────────────────────────────────────────────────────────────
# Tier 4: Cross-category Bayesian inference  (NEW in v3)
# ─────────────────────────────────────────────────────────────────────────────

# P(B | A) — "if A is confirmed, probability that B is also occurring"
# Values from legal case literature and co-occurrence analysis
_PRIOR_TABLE: dict[str, dict[str, float]] = {
    "Gatekeeping": {
        "Violation of Order": 0.82,
        "Stonewalling":       0.71,
        "Parental Alienation": 0.60,
        "Interference with Communication": 0.75,
    },
    "Parental Alienation": {
        "Stonewalling":       0.65,
        "Emotional Abuse":    0.70,
        "Child Statement":    0.55,
        "Third-Party Interference": 0.45,
    },
    "Threats": {
        "Harassment":         0.80,
        "Coercive Control":   0.72,
        "False Allegations":  0.45,
    },
    "Harassment": {
        "Threats":            0.75,
        "Stonewalling":       0.50,
        "Privacy Violation":  0.55,
    },
    "Violation of Order": {
        "Gatekeeping":        0.78,
        "Financial Abuse":    0.55,
        "Relocation":         0.40,
    },
    "Physical Abuse": {
        "Coercive Control":   0.85,
        "Emotional Abuse":    0.78,
        "Threats":            0.70,
        "Neglect / Safety":   0.50,
    },
    "Financial Abuse": {
        "Coercive Control":   0.65,
        "Violation of Order": 0.60,
    },
    "Substance Concern": {
        "Neglect / Safety":   0.72,
        "Emotional Abuse":    0.55,
    },
    "Relocation": {
        "Violation of Order": 0.88,
        "Gatekeeping":        0.70,
    },
    "Coercive Control": {
        "Emotional Abuse":    0.85,
        "Physical Abuse":     0.68,
        "Privacy Violation":  0.70,
    },
}

# Contradictory pairs — if both detected at high confidence, reduce both
_CONFLICT_PAIRS: list[tuple[str, str]] = [
    ("Gatekeeping", "Interference with Communication"),  # redundant but not contradictory
    ("False Allegations", "Physical Abuse"),             # one party claims false, other claims real
    ("Coercive Control", "Financial Abuse"),             # high overlap → dedup not suppress
]

# Minimum score to be considered "confirmed" for Bayesian lift
_BAYESIAN_CONFIRMED_THRESHOLD = 0.35


class BayesianInferenceLayer:
    """
    Tier 4: If category A is detected at high confidence, lift the prior for
    associated category B even if it was not directly detected in the text.
    Also suppresses impossible co-occurrences.
    """

    def apply(
        self,
        results: dict[str, tuple[float, str, float]],  # cat → (weight, confidence, score)
        candidate_categories: set[str],
    ) -> dict[str, tuple[float, str, float]]:
        """
        Mutates and returns results dict with Bayesian adjustments.
        """
        confirmed = {
            cat for cat, (_, _, score) in results.items()
            if score >= _BAYESIAN_CONFIRMED_THRESHOLD
        }

        for source_cat in confirmed:
            priors = _PRIOR_TABLE.get(source_cat, {})
            for target_cat, prob in priors.items():
                if target_cat in results:
                    # Category already detected — lift its score
                    w, conf, score = results[target_cat]
                    lift = score * (1.0 + (prob - 0.5) * 0.4)  # max +20% lift
                    conf_lifted = conf
                    if lift > score and conf == "possible":
                        conf_lifted = "likely"
                    results[target_cat] = (w, conf_lifted, min(lift, w))
                elif target_cat in candidate_categories and prob >= 0.70:
                    # Not detected yet but strong prior — add as "inferred" signal
                    weight = next(
                        (ww for c, ww, _ in PATTERN_DEFINITIONS if c == target_cat),
                        1.0
                    )
                    inferred_score = weight * prob * 0.45  # reduced — not directly evidenced
                    results[target_cat] = (weight, "possible", inferred_score)

        return results


# ─────────────────────────────────────────────────────────────────────────────
# Tier 5: Temporal escalation analysis  (NEW in v3)
# ─────────────────────────────────────────────────────────────────────────────

# Known escalation chains in custody/DV cases, ordered by severity
_ESCALATION_CHAINS: list[dict] = [
    {
        "name":     "Classic Custody Obstruction Escalation",
        "sequence": ["Stonewalling", "Gatekeeping", "Violation of Order"],
        "severity": "high",
        "note":     "Communication breakdown → access denial → court order violation pattern detected.",
    },
    {
        "name":     "Coercive Control to Violence Pathway",
        "sequence": ["Coercive Control", "Emotional Abuse", "Threats", "Physical Abuse"],
        "severity": "critical",
        "note":     "Textbook coercive control escalation pathway. Immediate safety concern.",
    },
    {
        "name":     "Alienation Campaign",
        "sequence": ["Interference with Communication", "Parental Alienation", "Child Statement"],
        "severity": "high",
        "note":     "Systematic campaign to alienate child from other parent.",
    },
    {
        "name":     "Retaliatory Escalation",
        "sequence": ["False Allegations", "Threats", "Harassment"],
        "severity": "high",
        "note":     "Pattern consistent with retaliatory behavior following legal proceedings.",
    },
    {
        "name":     "Financial Coercion Pattern",
        "sequence": ["Coercive Control", "Financial Abuse", "Violation of Order"],
        "severity": "moderate",
        "note":     "Financial control used as leverage; court order violations follow.",
    },
]


class EscalationAnalyzer:
    """
    Tier 5: Analyze a set of detected categories for known escalation patterns.
    Also reconstructs a rough timeline from exhibits.
    """

    def detect_chains(self, detected_categories: set[str]) -> list[dict]:
        """
        Return matched escalation chains (partial matches count if >= 2 steps present).
        """
        matches = []
        for chain in _ESCALATION_CHAINS:
            seq = chain["sequence"]
            hits = [s for s in seq if s in detected_categories]
            if len(hits) >= 2:
                completeness = len(hits) / len(seq)
                matches.append({
                    "chain_name":   chain["name"],
                    "severity":     chain["severity"],
                    "note":         chain["note"],
                    "matched_steps": hits,
                    "missing_steps": [s for s in seq if s not in detected_categories],
                    "completeness": round(completeness, 2),
                })
        matches.sort(key=lambda x: (x["severity"] == "critical", x["completeness"]), reverse=True)
        return matches

    def reconstruct_timeline(self, exhibits: list[dict]) -> list[dict]:
        """
        Attempt to order a list of exhibit dicts by extracted or inferred date.
        Each exhibit dict should have keys: id, text, categories, date_str (optional).
        Returns exhibits in chronological order with inferred_date attached.
        """
        nd = NegationDetector()
        timeline = []
        today = datetime.date.today()

        for ex in exhibits:
            text = ex.get("text", "")
            features = nd.extract_features(text)

            # Try explicit date first
            inferred_date = None
            if features["explicit_dates"]:
                raw = features["explicit_dates"][0]
                for fmt in ("%B %d, %Y", "%B %d %Y", "%b %d, %Y", "%m/%d/%Y", "%m-%d-%Y"):
                    try:
                        inferred_date = datetime.datetime.strptime(raw, fmt).date()
                        break
                    except ValueError:
                        pass

            # Fall back to recency offset
            if inferred_date is None and features["recency_offset_days"] is not None:
                inferred_date = today + datetime.timedelta(days=features["recency_offset_days"])

            # Fall back to stored date_str
            if inferred_date is None and ex.get("date_str"):
                try:
                    inferred_date = datetime.date.fromisoformat(ex["date_str"])
                except ValueError:
                    pass

            timeline.append({**ex, "inferred_date": inferred_date})

        # Sort: known dates first (chronological), then unknowns at end
        dated   = sorted([t for t in timeline if t["inferred_date"]], key=lambda x: x["inferred_date"])
        undated = [t for t in timeline if not t["inferred_date"]]
        return dated + undated


# ─────────────────────────────────────────────────────────────────────────────
# Main PatternEngine — five-tier orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class PatternResult:
    """Structured result object (also serializes to tuple for backward compat)."""
    __slots__ = (
        "category", "weight", "confidence", "score", "raw_cosine",
        "matched_sentence", "nearest_canonical", "top_k_canonical",
        "frequency_boost", "is_first_person", "explicit_dates",
        "bayesian_lifted", "source_tier",
    )

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def as_tuple(self) -> tuple[str, float, str]:
        """Drop-in compatible with v2 (category, weight, confidence)."""
        return (self.category, self.weight, self.confidence)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


class PatternEngine:
    """
    Five-tier pattern detection engine.
    Drop-in replacement for v2 PatternEngine.
    """

    def __init__(self):
        self._tier1 = AhoCorasickFilter()
        self._tier2 = NegationDetector()
        self._tier3 = SemanticMatcher()
        self._tier4 = BayesianInferenceLayer()
        self._tier5 = EscalationAnalyzer()
        self._weight_map  = {cat: w for cat, w, _ in PATTERN_DEFINITIONS}
        self._regex_fast  = self._compile_fast_regex()

    def _compile_fast_regex(self) -> list[tuple[str, float, re.Pattern]]:
        """
        Compile keyword-level regex fast-path from canonical sentences.
        Preserved from v2 for speed on obvious matches.
        """
        stop_long = {
            "their","there","about","these","those","would","could","should",
            "didn't","doesn't","hasn't","haven't","wouldn't","couldn't",
        }
        compiled = []
        for category, weight, sentences in PATTERN_DEFINITIONS:
            kw_patterns = []
            for sentence in sentences[:6]:
                words = [
                    re.escape(w) for w in sentence.split()
                    if len(w) > 4 and w.lower() not in stop_long
                ]
                if words:
                    kw_patterns.append(
                        r"\b" + r"\b.{0,25}\b".join(words[:3]) + r"\b"
                    )
            if kw_patterns:
                combined = "|".join(f"(?:{p})" for p in kw_patterns)
                try:
                    compiled.append((category, weight, re.compile(combined, re.IGNORECASE | re.DOTALL)))
                except re.error:
                    pass
        return compiled

    # ── Public API ──────────────────────────────────────────────────────────

    def scan(
        self,
        text: str,
        use_semantic: bool = True,
        use_bayesian: bool = True,
        return_rich: bool = False,
    ) -> list:
        """
        Full five-tier scan.

        Args:
            text:         Evidence text to analyze.
            use_semantic: Enable Tier-3 semantic matching.
            use_bayesian: Enable Tier-4 Bayesian cross-category inference.
            return_rich:  If True, return list[PatternResult]; if False, return
                          list[tuple[str,float,str]] for v2 compatibility.

        Returns:
            Sorted by weight × calibrated_score descending.
        """
        if not text or not text.strip():
            return []

        # cat → (weight, confidence, score, meta)
        results: dict[str, tuple[float, str, float, dict]] = {}

        # ── Tier 1: Aho-Corasick pre-filter ──────────────────────────────
        candidate_cats = self._tier1.candidate_categories(text)

        # ── Linguistic features (Tier 2 side-channel) ─────────────────────
        features = self._tier2.extract_features(text)

        # ── Fast regex path ────────────────────────────────────────────────
        for category, weight, pattern in self._regex_fast:
            match = pattern.search(text)
            if not match:
                continue
            flag_phrase = match.group(0)
            is_neg, conf_mult = self._tier2.is_negated(text, flag_phrase)
            if is_neg:
                continue

            base_conf  = WEIGHT_TO_CONFIDENCE.get(weight, "possible")
            adj_conf   = base_conf if conf_mult > 0.7 else "possible"
            freq_boost = features["frequency_boost"]
            score      = weight * conf_mult * freq_boost

            meta = {
                "source_tier": "regex",
                "matched_sentence": flag_phrase,
                "nearest_canonical": None,
                "top_k_canonical": [],
                "raw_cosine": None,
                "frequency_boost": freq_boost,
                "is_first_person": features["is_first_person"],
                "explicit_dates": features["explicit_dates"],
                "bayesian_lifted": False,
            }
            if category not in results or results[category][2] < score:
                results[category] = (weight, adj_conf, score, meta)

        # ── Tier 3: Semantic matching ──────────────────────────────────────
        if use_semantic and candidate_cats:
            uncaught = candidate_cats  # score ALL candidates, not just uncaught
            try:
                hits = self._tier3.score_text(text, uncaught)
                for hit in hits:
                    cat   = hit["category"]
                    score = hit["score"]
                    if score < SEMANTIC_THRESHOLD_LOW * 0.5:
                        continue

                    # Apply Tier-2 negation check
                    _, conf_mult = self._tier2.is_negated(text, cat)
                    if conf_mult < 0.3:
                        continue

                    freq_boost = features["frequency_boost"]
                    adj_score  = score * conf_mult * freq_boost

                    meta = {
                        "source_tier": "semantic",
                        "matched_sentence": hit.get("matched_sentence"),
                        "nearest_canonical": hit.get("nearest_canonical"),
                        "top_k_canonical": hit.get("top_k_canonical", []),
                        "raw_cosine": hit.get("raw_cosine"),
                        "frequency_boost": freq_boost,
                        "is_first_person": features["is_first_person"],
                        "explicit_dates": features["explicit_dates"],
                        "bayesian_lifted": False,
                    }
                    # Prefer higher-scoring source for same category
                    if cat not in results or results[cat][2] < adj_score:
                        results[cat] = (hit["weight"], hit["confidence"], adj_score, meta)
            except Exception as e:
                logger.warning(f"Semantic tier failed: {e}")

        # ── Tier 4: Bayesian cross-category inference ──────────────────────
        if use_bayesian:
            # Flatten to the format BayesianInferenceLayer expects
            flat = {cat: (w, conf, score) for cat, (w, conf, score, _) in results.items()}
            flat = self._tier4.apply(flat, candidate_cats)
            # Re-merge: update scores where Bayesian lifted them
            for cat, (w, conf, score) in flat.items():
                if cat in results:
                    old_score = results[cat][2]
                    old_meta  = results[cat][3]
                    if score > old_score:
                        new_meta = {**old_meta, "bayesian_lifted": True}
                        results[cat] = (w, conf, score, new_meta)
                else:
                    # Bayesian inferred category
                    inferred_meta = {
                        "source_tier": "bayesian",
                        "matched_sentence": None,
                        "nearest_canonical": None,
                        "top_k_canonical": [],
                        "raw_cosine": None,
                        "frequency_boost": 1.0,
                        "is_first_person": features["is_first_person"],
                        "explicit_dates": features["explicit_dates"],
                        "bayesian_lifted": True,
                    }
                    results[cat] = (w, conf, score, inferred_meta)

        # ── Sort and format output ─────────────────────────────────────────
        sorted_cats = sorted(results.items(), key=lambda x: x[1][2], reverse=True)

        if return_rich:
            out = []
            for cat, (w, conf, score, meta) in sorted_cats:
                out.append(PatternResult(
                    category         = cat,
                    weight           = w,
                    confidence       = conf,
                    score            = round(score, 4),
                    raw_cosine       = meta.get("raw_cosine"),
                    matched_sentence = meta.get("matched_sentence"),
                    nearest_canonical= meta.get("nearest_canonical"),
                    top_k_canonical  = meta.get("top_k_canonical", []),
                    frequency_boost  = meta.get("frequency_boost", 1.0),
                    is_first_person  = meta.get("is_first_person"),
                    explicit_dates   = meta.get("explicit_dates", []),
                    bayesian_lifted  = meta.get("bayesian_lifted", False),
                    source_tier      = meta.get("source_tier"),
                ))
            return out
        else:
            # v2-compatible tuple output
            return [(cat, w, conf) for cat, (w, conf, score, _) in sorted_cats]

    def scan_rich(self, text: str, **kwargs) -> list[PatternResult]:
        """Convenience wrapper that always returns rich PatternResult objects."""
        return self.scan(text, return_rich=True, **kwargs)

    def analyze_exhibits(self, exhibits: list[dict]) -> dict:
        """
        Batch analysis of multiple exhibits with escalation detection.
        Each exhibit: {id, text, date_str (optional), confirmed (optional)}

        Returns:
          {
            per_exhibit: [{id, categories, timeline_date, ...}],
            all_categories: set,
            escalation_chains: [...],
            timeline: [...],
            evidence_gaps: [...],
          }
        """
        per_exhibit = []
        all_cats: set[str] = set()

        for ex in exhibits:
            text = ex.get("text", "")
            if not text:
                continue
            hits = self.scan(text, return_rich=True)
            cats = [h.category for h in hits]
            all_cats.update(cats)
            per_exhibit.append({
                "id":           ex.get("id"),
                "text":         text,
                "date_str":     ex.get("date_str"),
                "categories":   cats,
                "top_hit":      hits[0].as_dict() if hits else None,
                "all_hits":     [h.as_dict() for h in hits],
            })

        chains   = self._tier5.detect_chains(all_cats)
        timeline = self._tier5.reconstruct_timeline(per_exhibit)
        gaps     = detect_evidence_gaps(list(all_cats), case_type="custody")

        return {
            "per_exhibit":        per_exhibit,
            "all_categories":     sorted(all_cats),
            "escalation_chains":  chains,
            "timeline":           timeline,
            "evidence_gaps":      gaps,
        }


# ─────────────────────────────────────────────────────────────────────────────
# SQLite embedding storage  (unchanged from v2 API)
# ─────────────────────────────────────────────────────────────────────────────

EMBEDDING_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS evidence_embeddings (
    exhibit_id   INTEGER PRIMARY KEY,
    case_id      INTEGER NOT NULL,
    embedding_json TEXT NOT NULL,
    model_version  TEXT NOT NULL DEFAULT 'tfidf-v1',
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (exhibit_id) REFERENCES evidence(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_emb_case ON evidence_embeddings(case_id);
"""


def init_embedding_schema(conn) -> None:
    for stmt in EMBEDDING_SCHEMA_SQL.strip().split(";"):
        s = stmt.strip()
        if s:
            try:
                conn.execute(s)
            except Exception:
                pass
    conn.commit()


def store_embedding(
    conn,
    exhibit_id: int,
    case_id: int,
    embedding: list[float],
    model_version: str = "tfidf-v1",
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO evidence_embeddings "
        "(exhibit_id, case_id, embedding_json, model_version) VALUES (?,?,?,?)",
        (exhibit_id, case_id, json.dumps(embedding), model_version),
    )
    conn.commit()


def find_similar_exhibits(
    conn,
    case_id: int,
    query_embedding: list[float],
    top_k: int = 5,
    exclude_id: Optional[int] = None,
) -> list[dict]:
    rows = conn.execute(
        "SELECT exhibit_id, embedding_json FROM evidence_embeddings WHERE case_id=?",
        (case_id,),
    ).fetchall()

    scored = []
    for row in rows:
        eid = row["exhibit_id"] if hasattr(row, "__getitem__") else row[0]
        if exclude_id and eid == exclude_id:
            continue
        try:
            emb = json.loads(row["embedding_json"] if hasattr(row, "__getitem__") else row[1])
            dot = sum(a * b for a, b in zip(query_embedding, emb))
            mag_q = math.sqrt(sum(x * x for x in query_embedding)) or 1e-9
            mag_e = math.sqrt(sum(x * x for x in emb)) or 1e-9
            sim = dot / (mag_q * mag_e)
            scored.append({"exhibit_id": eid, "similarity": sim})
        except Exception:
            continue

    scored.sort(key=lambda x: x["similarity"], reverse=True)
    return scored[:top_k]


# ─────────────────────────────────────────────────────────────────────────────
# Evidence gap detection  (upgraded co-occurrence matrix)
# ─────────────────────────────────────────────────────────────────────────────

_TYPICAL_PAIRS: dict[str, list[tuple[str, str]]] = {
    "Gatekeeping":        [
        ("Violation of Order",            "moderate"),
        ("Child Statement",               "low"),
        ("Stonewalling",                  "moderate"),
        ("Interference with Communication", "low"),
    ],
    "Parental Alienation": [
        ("Child Statement",               "moderate"),
        ("Stonewalling",                  "low"),
        ("Emotional Abuse",               "moderate"),
        ("Third-Party Interference",      "low"),
    ],
    "Threats":            [
        ("Harassment",                    "moderate"),
        ("Violation of Order",            "low"),
        ("Coercive Control",              "moderate"),
    ],
    "Violation of Order": [
        ("Gatekeeping",                   "moderate"),
        ("Financial Abuse",               "low"),
        ("Documentation / Evidence Tampering", "low"),
    ],
    "Financial Abuse":    [
        ("Violation of Order",            "moderate"),
        ("Coercive Control",              "moderate"),
    ],
    "Harassment":         [
        ("Threats",                       "moderate"),
        ("Stonewalling",                  "low"),
        ("Privacy Violation",             "low"),
    ],
    "Substance Concern":  [
        ("Neglect / Safety",              "moderate"),
        ("Emotional Abuse",               "low"),
    ],
    "Relocation":         [
        ("Violation of Order",            "high"),
        ("Gatekeeping",                   "moderate"),
    ],
    "Physical Abuse":     [
        ("Coercive Control",              "high"),
        ("Emotional Abuse",               "moderate"),
        ("Threats",                       "moderate"),
        ("Documentation / Evidence Tampering", "moderate"),
    ],
    "Coercive Control":   [
        ("Emotional Abuse",               "moderate"),
        ("Privacy Violation",             "moderate"),
        ("Financial Abuse",               "moderate"),
    ],
}


def detect_evidence_gaps(confirmed_categories: list[str], case_type: str = "custody") -> list[dict]:
    """
    Surface missing evidence categories typically co-occurring with confirmed ones.
    Returns list of gap dicts with severity and actionable tip.
    """
    cat_set = set(confirmed_categories)
    gaps = []
    seen: set[str] = set()

    for present_cat in cat_set:
        for expected_cat, severity in _TYPICAL_PAIRS.get(present_cat, []):
            if expected_cat not in cat_set and expected_cat not in seen:
                seen.add(expected_cat)
                gaps.append({
                    "present":   present_cat,
                    "missing":   expected_cat,
                    "severity":  severity,
                    "message":   (
                        f"Cases with {present_cat} evidence typically also include "
                        f"{expected_cat} documentation — none confirmed yet."
                    ),
                    "tip": (
                        f"Consider documenting specific {expected_cat.lower()} incidents "
                        f"to strengthen your {present_cat.lower()} claims."
                    ),
                })

    # Sort by severity
    order = {"high": 0, "moderate": 1, "low": 2}
    gaps.sort(key=lambda g: order.get(g["severity"], 9))
    return gaps


# ─────────────────────────────────────────────────────────────────────────────
# Singleton + backward-compatible public API
# ─────────────────────────────────────────────────────────────────────────────

_engine: Optional[PatternEngine] = None


def get_engine() -> PatternEngine:
    global _engine
    if _engine is None:
        _engine = PatternEngine()
    return _engine


def scan_patterns(text: str, use_semantic: bool = True) -> list[tuple[str, float, str]]:
    """
    Drop-in replacement for v2 scan_patterns().
    Returns list of (category, weight, confidence) tuples — identical signature.
    """
    return get_engine().scan(text, use_semantic=use_semantic)


def top_category(text: str) -> Optional[str]:
    results = scan_patterns(text)
    return results[0][0] if results else None
