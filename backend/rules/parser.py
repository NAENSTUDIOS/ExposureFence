"""
ExposureFence — Safe Declarative YAML Parser
Pure-Python, zero-dependency safe YAML parser and rule loader.
Guarantees zero arbitrary code execution and strict schema enforcement.
"""

import re
from typing import Any, Dict, List, Optional, Tuple, Union

from backend.rules.exceptions import RuleSyntaxError, UntrustedRuleContentError
from backend.rules.models import (
    OperatorType,
    Rule,
    RuleCondition,
    RuleSeverity,
    RuleType,
)


FORBIDDEN_TAG_PATTERN = re.compile(r"!\w+|!!\w+")


def _parse_scalar(val: str) -> Any:
    """Parses a YAML scalar string into the appropriate Python type."""
    val = val.strip()
    if not val:
        return ""
    if val in ("null", "None", "~"):
        return None
    if val.lower() in ("true", "yes", "on"):
        return True
    if val.lower() in ("false", "no", "off"):
        return False
    # Check quoted string
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        if len(val) >= 2:
            inner = val[1:-1]
            if val.startswith('"'):
                # Unescape common escapes
                inner = (
                    inner.replace('\\"', '"')
                    .replace('\\n', '\n')
                    .replace('\\t', '\t')
                    .replace('\\\\', '\\')
                )
            return inner
    # Integer check
    if re.fullmatch(r"[-+]?\d+", val):
        try:
            return int(val)
        except ValueError:
            pass
    # Float check
    if re.fullmatch(r"[-+]?\d+\.\d+", val):
        try:
            return float(val)
        except ValueError:
            pass
    return val


def _strip_inline_comment(line: str) -> str:
    """Strips comments from a line, respecting quoted substrings."""
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == '#' and not in_single and not in_double:
            # Comment starts if preceding is whitespace or start
            if i == 0 or line[i - 1].isspace():
                return line[:i]
    return line


class SafeYAMLParser:
    """
    Zero-dependency safe recursive-descent YAML subset parser.
    Parses mappings, lists, strings, numbers, booleans, and nulls.
    Strictly forbids unsafe execution tags.
    """

    def __init__(self, text: str):
        self.raw_text = text
        self.lines: List[Tuple[int, int, str]] = []  # (line_number, indent, content)
        self._preprocess()

    def _preprocess(self):
        for line_no, raw_line in enumerate(self.raw_text.splitlines(), start=1):
            stripped = _strip_inline_comment(raw_line).rstrip()
            if not stripped or stripped.isspace():
                continue

            # Security: check for unsafe tags
            if FORBIDDEN_TAG_PATTERN.search(stripped):
                raise UntrustedRuleContentError(
                    f"Line {line_no}: Untrusted YAML tag detected in rule file: '{stripped.strip()}'. "
                    f"Arbitrary object instantiation and custom tags are strictly forbidden."
                )

            indent = len(stripped) - len(stripped.lstrip())
            content = stripped.lstrip()
            self.lines.append((line_no, indent, content))

    def parse(self) -> Any:
        if not self.lines:
            return {}
        idx, result = self._parse_block(0, self.lines[0][1])
        return result

    def _parse_block(self, start_idx: int, block_indent: int) -> Tuple[int, Any]:
        if start_idx >= len(self.lines):
            return start_idx, None

        first_line_no, first_indent, first_content = self.lines[start_idx]
        if first_indent < block_indent:
            return start_idx, None

        if first_content.startswith("-"):
            return self._parse_list(start_idx, block_indent)
        else:
            return self._parse_mapping(start_idx, block_indent)

    def _parse_list(self, start_idx: int, list_indent: int) -> Tuple[int, List[Any]]:
        items = []
        idx = start_idx
        while idx < len(self.lines):
            line_no, indent, content = self.lines[idx]
            if indent < list_indent:
                break
            if indent > list_indent and not content.startswith("-"):
                # Nested content belonging to previous list item
                break
            if not content.startswith("-"):
                break

            # Strip '-' and examine remainder
            item_text = content[1:].strip()
            if not item_text:
                # Next lines are the child block
                idx += 1
                if idx < len(self.lines) and self.lines[idx][1] > indent:
                    child_indent = self.lines[idx][1]
                    idx, child_val = self._parse_block(idx, child_indent)
                    items.append(child_val)
                else:
                    items.append(None)
            elif ":" in item_text:
                # List item is the first key of a mapping, e.g. "- id: R01"
                key, val = item_text.split(":", 1)
                key = key.strip()
                val = val.strip()

                sub_map: Dict[str, Any] = {}
                if val:
                    sub_map[key] = _parse_scalar(val)
                    idx += 1
                else:
                    # Key with nested children
                    idx += 1
                    if idx < len(self.lines) and self.lines[idx][1] > indent:
                        child_indent = self.lines[idx][1]
                        idx, child_val = self._parse_block(idx, child_indent)
                        sub_map[key] = child_val
                    else:
                        sub_map[key] = None

                # Collect subsequent sibling keys at child indent (> list_indent)
                child_indent = indent + 2
                while idx < len(self.lines):
                    next_line_no, next_indent, next_content = self.lines[idx]
                    if next_indent < child_indent or next_content.startswith("-"):
                        break
                    if ":" in next_content:
                        k, v = next_content.split(":", 1)
                        k = k.strip()
                        v = v.strip()
                        if v:
                            sub_map[k] = _parse_scalar(v)
                            idx += 1
                        else:
                            idx += 1
                            if idx < len(self.lines) and self.lines[idx][1] > next_indent:
                                sub_child_indent = self.lines[idx][1]
                                idx, sub_child_val = self._parse_block(idx, sub_child_indent)
                                sub_map[k] = sub_child_val
                            else:
                                sub_map[k] = None
                    else:
                        break
                items.append(sub_map)
            else:
                # Simple scalar item
                items.append(_parse_scalar(item_text))
                idx += 1
        return idx, items

    def _parse_mapping(self, start_idx: int, map_indent: int) -> Tuple[int, Dict[str, Any]]:
        mapping = {}
        idx = start_idx
        while idx < len(self.lines):
            line_no, indent, content = self.lines[idx]
            if indent < map_indent:
                break
            if indent > map_indent:
                break
            if content.startswith("-"):
                break

            if ":" not in content:
                raise RuleSyntaxError(f"Line {line_no}: Expected key-value pair, found: '{content}'")

            key, val = content.split(":", 1)
            key = key.strip()
            val = val.strip()

            if val:
                mapping[key] = _parse_scalar(val)
                idx += 1
            else:
                # Key with block child (dict or list)
                idx += 1
                if idx < len(self.lines) and self.lines[idx][1] > indent:
                    child_indent = self.lines[idx][1]
                    idx, child_val = self._parse_block(idx, child_indent)
                    mapping[key] = child_val
                else:
                    mapping[key] = None

        return idx, mapping


def safe_load_yaml(yaml_str: str) -> Any:
    """Parses a YAML string securely without evaluating arbitrary code."""
    # Attempt pyyaml if installed, but enforce safe_load
    try:
        import yaml
        # Security: verify no custom tags before calling pyyaml
        if FORBIDDEN_TAG_PATTERN.search(yaml_str):
            raise UntrustedRuleContentError("Untrusted YAML tag detected in rule file.")
        return yaml.safe_load(yaml_str) or {}
    except (ImportError, ModuleNotFoundError):
        parser = SafeYAMLParser(yaml_str)
        return parser.parse()


def load_yaml_file(filepath: str) -> Any:
    """Reads and parses a YAML file from disk."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    return safe_load_yaml(content)


def parse_condition_dict(cond_dict: Dict[str, Any]) -> RuleCondition:
    """Parses a single condition dictionary into a RuleCondition."""
    field_name = cond_dict.get("field")
    if not field_name:
        raise RuleSyntaxError("Condition missing required 'field' property")

    op_str = cond_dict.get("operator", "EQUALS").upper()
    try:
        operator = OperatorType(op_str)
    except ValueError:
        try:
            operator = OperatorType[op_str]
        except KeyError:
            raise RuleSyntaxError(f"Unknown condition operator: '{op_str}'")

    expected_val = cond_dict.get("expected_value")
    desc = cond_dict.get("description")
    return RuleCondition(
        field=field_name,
        operator=operator,
        expected_value=expected_val,
        description=desc,
    )


def parse_rule_dict(data: Dict[str, Any]) -> Rule:
    """Constructs a Rule dataclass instance from a dictionary."""
    rule_id = data.get("id")
    if not rule_id:
        raise RuleSyntaxError("Rule missing required 'id' attribute")

    description = data.get("description", "")
    allowed_action = data.get("allowed_action", "")
    forbidden_action = data.get("forbidden_action", "")
    enforcement_layer = data.get("enforcement_layer", "Application Boundary")
    test_id = data.get("test_id", "")
    proof = data.get("proof", "")

    # Severity
    sev_str = str(data.get("severity", "HIGH")).upper()
    try:
        severity = RuleSeverity(sev_str)
    except ValueError:
        severity = RuleSeverity.HIGH

    # Rule type
    type_str = str(data.get("rule_type", "INVARIANT_TEST")).upper()
    try:
        rule_type = RuleType(type_str)
    except ValueError:
        rule_type = RuleType.INVARIANT_TEST

    target = data.get("target_resource_type") or data.get("target")

    # Conditions
    conditions = []
    raw_conds = data.get("conditions", [])
    if isinstance(raw_conds, list):
        for raw_c in raw_conds:
            if isinstance(raw_c, dict):
                conditions.append(parse_condition_dict(raw_c))

    remediation = data.get("remediation_template")
    version = data.get("version", "1.0.0")

    return Rule(
        id=rule_id,
        description=description,
        allowed_action=allowed_action,
        forbidden_action=forbidden_action,
        enforcement_layer=enforcement_layer,
        test_id=test_id,
        proof=proof,
        severity=severity,
        rule_type=rule_type,
        target_resource_type=target,
        conditions=conditions,
        remediation_template=remediation,
        version=version,
    )


def load_rules_from_yaml(filepath: str) -> List[Rule]:
    """Loads and validates all rules defined in a YAML file."""
    raw_data = load_yaml_file(filepath)
    if not isinstance(raw_data, dict):
        raise RuleSyntaxError("Root of rules YAML file must be a dictionary with a 'rules' key")

    raw_rules = raw_data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise RuleSyntaxError("'rules' key in YAML file must contain a list of rule definitions")

    rules = []
    for raw_rule in raw_rules:
        if isinstance(raw_rule, dict):
            rules.append(parse_rule_dict(raw_rule))
    return rules
