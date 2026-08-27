"""
MIRAGE Auto Rule Generator
When ML detects a new attack, automatically generate WAF rules
So next time, the attack is blocked at pattern level (never reaches ML)
"""
import re
import time
import json
import hashlib
import threading
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict

@dataclass
class GeneratedRule:
    """Auto-generated WAF rule"""
    rule_id: str
    pattern: str
    category: str
    description: str
    confidence: float
    created_at: float
    source: str  # "ml", "zero_day", "honeypot"
    hits: int = 0
    false_positives: int = 0
    
    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "pattern": self.pattern,
            "category": self.category,
            "description": self.description,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "source": self.source,
            "hits": self.hits,
            "false_positives": self.false_positives,
        }


class RuleGenerator:
    """
    Automatically generates WAF rules from ML detections
    
    Flow:
    1. ML detects new attack
    2. Extract attack pattern
    3. Generate regex rule
    4. Add to dynamic rules
    5. Next similar attack → caught at WAF level
    """
    
    def __init__(self, storage_path: str = "./data/rules"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.rules: Dict[str, GeneratedRule] = {}
        self.pending_patterns: Dict[str, List[Dict]] = defaultdict(list)
        self.min_hits_for_rule = 2
        self.lock = threading.Lock()
        self._load_rules()
    
    def record_ml_detection(self, payload: str, category: str, confidence: float, 
                            path: str, method: str) -> Optional[GeneratedRule]:
        """Record ML detection and potentially generate a new rule"""
        with self.lock:
            pattern_signature = self._extract_pattern(payload, category)
            if not pattern_signature:
                return None
            
            pattern_hash = hashlib.sha256(pattern_signature.encode()).hexdigest()[:24]
            
            self.pending_patterns[pattern_hash].append({
                "payload": payload,
                "category": category,
                "confidence": confidence,
                "path": path,
                "timestamp": time.time(),
            })
            
            if len(self.pending_patterns[pattern_hash]) >= self.min_hits_for_rule:
                rule = self._generate_rule(pattern_signature, category, 
                                          self.pending_patterns[pattern_hash])
                if rule:
                    self.rules[rule.rule_id] = rule
                    self._save_rules()
                    del self.pending_patterns[pattern_hash]
                    return rule
            return None
    
    def _extract_pattern(self, payload: str, category: str) -> Optional[str]:
        """Extract generalizable pattern from payload"""
        extractors = {
            "SQLI": self._extract_sqli_pattern,
            "XSS": self._extract_xss_pattern,
            "RCE": self._extract_rce_pattern,
            "LFI": self._extract_lfi_pattern,
            "SSRF": self._extract_ssrf_pattern,
        }
        extractor = extractors.get(category.upper(), self._extract_generic_pattern)
        return extractor(payload)
    
    def _extract_sqli_pattern(self, payload: str) -> Optional[str]:
        patterns = []
        if re.search(r"union\s+select", payload, re.I): patterns.append("union_select")
        if re.search(r"['\"][\s]*(?:or|and)", payload, re.I): patterns.append("quote_logic")
        if re.search(r"(--|#|/\*)", payload): patterns.append("sql_comment")
        if re.search(r"sleep\s*\(|benchmark\s*\(|waitfor", payload, re.I): patterns.append("time_based")
        return f"sqli:{':'.join(sorted(set(patterns)))}" if patterns else None
    
    def _extract_xss_pattern(self, payload: str) -> Optional[str]:
        patterns = []
        if re.search(r"<\s*script", payload, re.I): patterns.append("script_tag")
        if re.search(r"on\w+\s*=", payload, re.I): patterns.append("event_handler")
        if re.search(r"javascript\s*:", payload, re.I): patterns.append("js_protocol")
        return f"xss:{':'.join(sorted(set(patterns)))}" if patterns else None
    
    def _extract_rce_pattern(self, payload: str) -> Optional[str]:
        patterns = []
        if re.search(r"[;&|`]", payload): patterns.append("cmd_chain")
        if re.search(r"\$[\(\{]|`", payload): patterns.append("cmd_subst")
        if re.search(r"\b(cat|ls|whoami|id|wget|curl|nc|bash)\b", payload, re.I): patterns.append("shell_cmd")
        return f"rce:{':'.join(sorted(set(patterns)))}" if patterns else None
    
    def _extract_lfi_pattern(self, payload: str) -> Optional[str]:
        patterns = []
        if re.search(r"\.\./|\.\.\\", payload): patterns.append("traversal")
        if re.search(r"(php|expect|data|zip)://", payload, re.I): patterns.append("wrapper")
        if "%00" in payload: patterns.append("null_byte")
        return f"lfi:{':'.join(sorted(set(patterns)))}" if patterns else None
    
    def _extract_ssrf_pattern(self, payload: str) -> Optional[str]:
        patterns = []
        if re.search(r"127\.0\.0\.1|localhost|\[::1\]", payload, re.I): patterns.append("localhost")
        if re.search(r"169\.254\.169\.254", payload): patterns.append("metadata")
        if re.search(r"file://|gopher://", payload, re.I): patterns.append("protocol")
        return f"ssrf:{':'.join(sorted(set(patterns)))}" if patterns else None
    
    def _extract_generic_pattern(self, payload: str) -> Optional[str]:
        suspicious = sum(1 for c in payload if c in '<>"\';|&$`')
        return f"suspicious:chars_{suspicious}" if suspicious >= 3 else None
    
    def _generate_rule(self, sig: str, category: str, detections: List[Dict]) -> Optional[GeneratedRule]:
        """Generate regex rule from pattern signature"""
        parts = sig.split(":")
        attack_type, indicators = parts[0], parts[1].split(":") if len(parts) > 1 else []
        
        regex_map = {
            "sqli": {
                "union_select": r"union[\s]+select",
                "quote_logic": r"['\"][\s]*(?:or|and)",
                "sql_comment": r"(--|#|/\*)",
                "time_based": r"(sleep|benchmark|waitfor)[\s]*\(",
            },
            "xss": {
                "script_tag": r"<[\s]*script",
                "event_handler": r"on\w+[\s]*=",
                "js_protocol": r"javascript[\s]*:",
            },
            "rce": {
                "cmd_chain": r"[;&|`][\s]*\w+",
                "cmd_subst": r"\$[\(\{]|`[^`]+`",
                "shell_cmd": r"\b(cat|ls|whoami|id|wget|curl|nc|bash)\b",
            },
            "lfi": {
                "traversal": r"\.\.(/|\\)",
                "wrapper": r"(php|expect|data|zip)://",
                "null_byte": r"%00",
            },
            "ssrf": {
                "localhost": r"(127\.0\.0\.1|localhost|\[::1\])",
                "metadata": r"169\.254\.169\.254",
                "protocol": r"(file|gopher)://",
            },
        }
        
        patterns = [regex_map.get(attack_type, {}).get(i) for i in indicators]
        patterns = [p for p in patterns if p]
        
        if not patterns:
            return None
        
        final_pattern = "|".join(f"({p})" for p in patterns)
        avg_conf = sum(d["confidence"] for d in detections) / len(detections)
        rule_id = f"AUTO-{hashlib.sha256(sig.encode()).hexdigest()[:16].upper()}"
        
        return GeneratedRule(
            rule_id=rule_id, pattern=final_pattern, category=category.upper(),
            description=f"Auto-generated: {sig}", confidence=min(avg_conf, 0.85),
            created_at=time.time(), source="ml", hits=len(detections),
        )
    
    def get_active_rules(self) -> List[GeneratedRule]:
        with self.lock:
            return [r for r in self.rules.values() 
                    if r.false_positives < 3 or r.hits / max(r.false_positives, 1) > 5]
    
    def get_rule_patterns(self) -> List[Tuple[str, str, str, float]]:
        return [(r.rule_id, r.pattern, r.category, r.confidence) for r in self.get_active_rules()]
    
    def record_rule_hit(self, rule_id: str):
        with self.lock:
            if rule_id in self.rules:
                self.rules[rule_id].hits += 1
    
    def record_false_positive(self, rule_id: str):
        with self.lock:
            if rule_id in self.rules:
                self.rules[rule_id].false_positives += 1
                if self.rules[rule_id].false_positives >= 5:
                    del self.rules[rule_id]
                    self._save_rules()
    
    def _save_rules(self):
        try:
            with open(self.storage_path / "auto_rules.json", 'w') as f:
                json.dump({k: v.to_dict() for k, v in self.rules.items()}, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save rules: {e}")
    
    def _load_rules(self):
        rules_path = self.storage_path / "auto_rules.json"
        if rules_path.exists():
            try:
                with open(rules_path) as f:
                    for rid, data in json.load(f).items():
                        self.rules[rid] = GeneratedRule(**data)
            except Exception as e:
                print(f"Warning: Could not load rules: {e}")
    
    def get_stats(self) -> Dict:
        with self.lock:
            return {
                "total_rules": len(self.rules),
                "pending_patterns": len(self.pending_patterns),
                "total_hits": sum(r.hits for r in self.rules.values()),
            }

rule_generator = RuleGenerator()
