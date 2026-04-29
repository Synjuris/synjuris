"""
pattern_engine.py — SynJuris v3 Advanced Pattern Detection Engine
"""
import re

class PatternEngine:
    def __init__(self):
        self.patterns = {
            "Gatekeeping": [r"refused access", r"denied visitation", r"withheld child"],
            "Violation of Order": [r"contempt", r"disobeyed", r"failed to return"],
            "Harassment": [r"threatened", r"excessive calls", r"insulted"]
        }

    def scan(self, text, use_semantic=False):
        results = []
        for cat, regexes in self.patterns.items():
            if any(re.search(r, text, re.I) for r in regexes):
                results.append((cat, 1.0, "high"))
        return sorted(results, key=lambda x: -x[1])

def scan_patterns(text, use_semantic=False):
    return PatternEngine().scan(text)
