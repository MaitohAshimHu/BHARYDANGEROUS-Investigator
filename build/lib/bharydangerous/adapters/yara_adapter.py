"""YARA scanning adapter supporting native bindings, CLI, and regex fallback."""
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from bharydangerous.adapters.base import is_tool_available, run_command_safely

class YaraScanMatch:
    def __init__(self, rule_name: str, tags: List[str], strings_matched: List[Dict[str, Any]], meta: Dict[str, Any]):
        self.rule_name = rule_name
        self.tags = tags
        self.strings_matched = strings_matched
        self.meta = meta

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule_name,
            "tags": self.tags,
            "strings": self.strings_matched,
            "meta": self.meta,
        }

class YaraAdapter:
    """Multi-mode YARA adapter."""

    def __init__(self, rules_dir: Optional[Path | str] = None):
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).parents[3] / "rules"
        self._yara_module = None
        try:
            import yara
            self._yara_module = yara
        except ImportError:
            self._yara_module = None

        self.has_cli = is_tool_available("yara")

    def scan_file(self, target_path: Path | str, rule_file: Optional[Path | str] = None) -> List[YaraScanMatch]:
        """Scan a file using python-yara, CLI yara, or fallback regex parser."""
        target = Path(target_path)
        if not target.is_file():
            raise FileNotFoundError(f"Target file not found: {target}")

        rule_paths = [Path(rule_file)] if rule_file else (list(self.rules_dir.glob("*.yar")) if self.rules_dir.is_dir() else [])

        all_matches: List[YaraScanMatch] = []

        # Mode 1: yara-python native module
        if self._yara_module and rule_paths:
            for rp in rule_paths:
                try:
                    rules = self._yara_module.compile(filepath=str(rp))
                    matches = rules.match(str(target))
                    for m in matches:
                        all_matches.append(
                            YaraScanMatch(
                                rule_name=m.rule,
                                tags=list(m.tags),
                                strings_matched=[{"identifier": s.identifier, "offset": s.instances[0].offset if s.instances else 0} for s in m.strings],
                                meta=dict(m.meta),
                            )
                        )
                except Exception:
                    pass
            if all_matches:
                return all_matches

        # Mode 2: yara CLI
        if self.has_cli and rule_paths:
            for rp in rule_paths:
                res = run_command_safely(["yara", "-m", "-s", str(rp), str(target)])
                if res.success:
                    all_matches.extend(self._parse_cli_yara_output(res.stdout))
            if all_matches:
                return all_matches

        # Mode 3: Built-in pure-Python rule matcher
        return self._fallback_rule_matcher(target, Path(rule_file) if rule_file else None)

    def _parse_cli_yara_output(self, output: str) -> List[YaraScanMatch]:
        matches: List[YaraScanMatch] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("0x"):
                continue
            parts = line.split()
            if parts:
                rule_name = parts[0]
                matches.append(YaraScanMatch(
                    rule_name=rule_name,
                    tags=[],
                    strings_matched=[],
                    meta={},
                ))
        return matches

    def _fallback_rule_matcher(self, target: Path, rule_path: Optional[Path]) -> List[YaraScanMatch]:
        """Fallback regex-based matcher for common YARA rule strings."""
        if not target.is_file():
            return []

        with target.open("rb") as f:
            content = f.read(10 * 1024 * 1024)  # 10 MB limit for fast scanning

        matches: List[YaraScanMatch] = []

        # Read rules from rule_path if available
        rule_texts = []
        if rule_path and rule_path.is_file():
            try:
                rule_texts.append(rule_path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
        elif self.rules_dir.is_dir():
            for rfile in self.rules_dir.glob("*.yar"):
                try:
                    rule_texts.append(rfile.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    pass

        # Extract rules and string patterns: $s = "string" or $s = /regex/
        for text in rule_texts:
            rule_blocks = re.findall(r"rule\s+([A-Za-z0-9_]+)\s*(?::\s*([^{]+))?\s*\{(.*?)\}", text, re.DOTALL)
            for rule_name, tag_str, body in rule_blocks:
                tags = [t.strip() for t in tag_str.split()] if tag_str else []
                # Extract strings section
                strings_match = re.search(r"strings:\s*(.*?)(?:condition:|\Z)", body, re.DOTALL)
                if not strings_match:
                    continue
                strings_section = strings_match.group(1)

                matched_strings = []
                # Find string definitions: $var = "literal"
                patterns = re.findall(r'(\$[a-zA-Z0-9_]+)\s*=\s*"([^"]+)"', strings_section)
                for var_name, lit_val in patterns:
                    lit_bytes = lit_val.encode("utf-8")
                    idx = content.find(lit_bytes)
                    if idx != -1:
                        matched_strings.append({"identifier": var_name, "offset": idx, "matched": lit_val})

                # Find hex patterns: $hex = { 4D 5A ... }
                hex_patterns = re.findall(r'(\$[a-zA-Z0-9_]+)\s*=\s*\{\s*([0-9a-fA-F\s]+)\s*\}', strings_section)
                for var_name, hex_str in hex_patterns:
                    hex_clean = "".join(hex_str.split())
                    if len(hex_clean) % 2 == 0:
                        try:
                            hb = bytes.fromhex(hex_clean)
                            idx = content.find(hb)
                            if idx != -1:
                                matched_strings.append({"identifier": var_name, "offset": idx, "matched": hex_str})
                        except Exception:
                            pass

                if matched_strings:
                    matches.append(YaraScanMatch(
                        rule_name=rule_name,
                        tags=tags,
                        strings_matched=matched_strings,
                        meta={"mode": "native_python_regex_fallback"},
                    ))

        return matches
