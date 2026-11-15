"""Solidity contract tokenizer, AST extractor, and EVM storage-slot layout analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from solguard.models import (
    EventDefinition,
    EventParameter,
    FunctionDefinition,
    FunctionParameter,
    ParsedContract,
    PragmaDirective,
    StatementInfo,
    StateVariable,
    StorageLayout,
    StorageSlot,
    StorageSlotItem,
    StructDefinition,
    StructField,
    evm_type_bytes,
    is_packable_type,
)

# Cold SSTORE (20,000 gas) + cold SLOAD (2,100 gas) saved per eliminated 32-byte storage slot
GAS_SAVED_PER_SLOT = 22_100

_PRAGMA_RE = re.compile(r"\bpragma\s+solidity\s+([^;]+);")
_CONTRACT_HEADER_RE = re.compile(
    r"\b(abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+is\s+([^{]+))?\s*\{"
)
_STRUCT_HEADER_RE = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
_EVENT_RE = re.compile(
    r"\bevent\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:anonymous\s*)?;"
)
_FUNC_HEADER_RE = re.compile(
    r"\b(?:(function)\s+([A-Za-z_][A-Za-z0-9_]*)|(constructor|receive|fallback))\s*\("
)
_MODIFIER_BLOCK_RE = re.compile(r"\bmodifier\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\([^)]*\))?\s*\{")
_ENUM_BLOCK_RE = re.compile(r"\benum\s+[A-Za-z_][A-Za-z0-9_]*\s*\{")
_SUPPRESSION_RE = re.compile(
    r"//\s*solguard-disable-(next-line|line)(?:\s+([A-Za-z0-9_,\s-]+))?"
)

_VISIBILITIES = {"external", "public", "internal", "private"}
_MUTABILITIES = {"pure", "view", "payable", "nonpayable"}
_DATA_LOCATIONS = {"memory", "calldata", "storage"}


def strip_comments_preserving_layout(source: str) -> str:
    """Replace // and /* */ comments with spaces while preserving newlines and offsets."""
    chars = list(source)
    n = len(chars)
    i = 0
    in_string: str | None = None

    while i < n:
        ch = chars[i]
        if in_string is not None:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue

        if ch in {'"', "'"}:
            in_string = ch
            i += 1
            continue

        # Single-line comment
        if ch == "/" and i + 1 < n and chars[i + 1] == "/":
            while i < n and chars[i] != "\n":
                chars[i] = " "
                i += 1
            continue

        # Multi-line comment
        if ch == "/" and i + 1 < n and chars[i + 1] == "*":
            chars[i] = " "
            chars[i + 1] = " "
            i += 2
            while i < n:
                if chars[i] == "*" and i + 1 < n and chars[i + 1] == "/":
                    chars[i] = " "
                    chars[i + 1] = " "
                    i += 2
                    break
                if chars[i] != "\n":
                    chars[i] = " "
                i += 1
            continue

        i += 1

    return "".join(chars)


def extract_suppressions(source: str) -> dict[int, set[str]]:
    """Extract inline `// solguard-disable-line` and `// solguard-disable-next-line` directives."""
    suppressions: dict[int, set[str]] = {}
    for idx, line_text in enumerate(source.splitlines(), start=1):
        match = _SUPPRESSION_RE.search(line_text)
        if not match:
            continue
        directive_kind = match.group(1)
        rules_raw = match.group(2)
        target_line = idx + 1 if directive_kind == "next-line" else idx
        if not rules_raw or not rules_raw.strip():
            rule_ids = {"ALL"}
        else:
            rule_ids = {
                token.strip().upper()
                for token in re.split(r"[,\s]+", rules_raw.strip())
                if token.strip()
            }
            if not rule_ids:
                rule_ids = {"ALL"}
        suppressions.setdefault(target_line, set()).update(rule_ids)
    return suppressions


def _line_number_at(source: str, offset: int) -> int:
    """Return 1-indexed line number for a character offset."""
    return source.count("\n", 0, offset) + 1


def _column_at(source: str, offset: int) -> int:
    """Return 1-indexed column number for a character offset."""
    last_nl = source.rfind("\n", 0, offset)
    if last_nl == -1:
        return offset + 1
    return offset - last_nl


def _find_matching_brace(source: str, open_brace_index: int) -> int:
    """Given the index of `{`, return the index of the matching `}`."""
    depth = 0
    in_string: str | None = None
    i = open_brace_index
    n = len(source)

    while i < n:
        ch = source[i]
        if in_string is not None:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue

        if ch in {'"', "'"}:
            in_string = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1

    return n - 1


def _find_matching_paren(source: str, open_paren_index: int) -> int:
    """Given the index of `(`, return the index of the matching `)`."""
    depth = 0
    i = open_paren_index
    n = len(source)
    while i < n:
        ch = source[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def _split_top_level_commas(text: str) -> list[str]:
    """Split a parameter list on commas, ignoring commas inside parentheses."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in text:
        if ch in "([":
            depth += 1
            current.append(ch)
        elif ch in ")]":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def parse_pragmas(clean_source: str) -> list[PragmaDirective]:
    """Extract all `pragma solidity ...;` directives."""
    pragmas: list[PragmaDirective] = []
    for match in _PRAGMA_RE.finditer(clean_source):
        constraint = " ".join(match.group(1).strip().split())
        line = _line_number_at(clean_source, match.start())
        has_caret_or_tilde = "^" in constraint or "~" in constraint or "*" in constraint
        has_unbounded_gt = (">" in constraint) and ("<" not in constraint)
        is_floating = has_caret_or_tilde or has_unbounded_gt
        pragmas.append(
            PragmaDirective(
                raw=match.group(0).strip(),
                version_constraint=constraint,
                line=line,
                is_floating=is_floating,
            )
        )
    return pragmas


def _simulate_sequential_slots(
    items: list[tuple[str, str, int, int]]
) -> list[StorageSlot]:
    """Simulate EVM sequential 32-byte slot allocation for `(name, type, bytes, line)` items."""
    slots: list[StorageSlot] = []
    current_slot: StorageSlot | None = None

    for name, type_name, byte_size, decl_line in items:
        packable = is_packable_type(type_name)
        if (
            current_slot is not None
            and packable
            and current_slot.used_bytes + byte_size <= 32
            and all(is_packable_type(existing.type_name) for existing in current_slot.items)
        ):
            offset = current_slot.used_bytes
            current_slot.items.append(
                StorageSlotItem(
                    name=name,
                    type_name=type_name,
                    byte_size=byte_size,
                    byte_offset=offset,
                    line=decl_line,
                )
            )
        else:
            slot_idx = len(slots)
            current_slot = StorageSlot(
                slot_index=slot_idx,
                items=[
                    StorageSlotItem(
                        name=name,
                        type_name=type_name,
                        byte_size=byte_size,
                        byte_offset=0,
                        line=decl_line,
                    )
                ],
            )
            slots.append(current_slot)
            if not packable or byte_size >= 32:
                current_slot = None

    return slots


def _compute_optimal_packing(
    items: list[tuple[str, str, int, int]]
) -> tuple[int, list[str]]:
    """Compute minimum 32-byte storage slots using First-Fit Decreasing (FFD) bin packing."""
    if not items:
        return 0, []

    bins: list[list[tuple[str, str, int, int]]] = []
    bin_used: list[int] = []

    # Sort descending by byte size while keeping full-slot / non-packable items first
    indexed_items = list(enumerate(items))
    indexed_items.sort(
        key=lambda pair: (
            0 if not is_packable_type(pair[1][1]) or pair[1][2] >= 32 else 1,
            -pair[1][2],
            pair[0],
        )
    )

    for _, item in indexed_items:
        _name, type_name, byte_size, _line = item
        if not is_packable_type(type_name) or byte_size >= 32:
            bins.append([item])
            bin_used.append(32)
            continue

        placed = False
        for idx, used in enumerate(bin_used):
            if used + byte_size <= 32:
                bins[idx].append(item)
                bin_used[idx] += byte_size
                placed = True
                break
        if not placed:
            bins.append([item])
            bin_used.append(byte_size)

    optimal_order = [item[0] for b in bins for item in b]
    return len(bins), optimal_order


def compute_storage_layout(
    target_name: str,
    kind: str,
    line: int,
    items: list[tuple[str, str, int, int]],
) -> StorageLayout:
    """Compute actual vs optimal EVM 32-byte storage layout for a contract or struct."""
    slots = _simulate_sequential_slots(items)
    total_slots = len(slots)
    optimal_slots, optimal_order = _compute_optimal_packing(items)
    slots_saved = max(0, total_slots - optimal_slots)
    return StorageLayout(
        target_name=target_name,
        kind=kind,
        line=line,
        slots=slots,
        total_slots=total_slots,
        optimal_slots=optimal_slots,
        optimal_order=optimal_order,
        estimated_gas_saved=slots_saved * GAS_SAVED_PER_SLOT,
    )


def _parse_function_parameters(param_str: str) -> list[FunctionParameter]:
    """Parse function parameter or return parameter list."""
    params: list[FunctionParameter] = []
    for raw_part in _split_top_level_commas(param_str):
        tokens = raw_part.split()
        if not tokens:
            continue

        data_location: str | None = None
        filtered: list[str] = []
        for tok in tokens:
            if tok in _DATA_LOCATIONS and data_location is None:
                data_location = tok
            elif tok == "payable":
                filtered.append(tok)
            else:
                filtered.append(tok)

        if len(filtered) >= 2 and not filtered[-1].endswith("]") and filtered[-1] != "payable":
            param_name = filtered[-1]
            type_name = " ".join(filtered[:-1])
        else:
            param_name = ""
            type_name = " ".join(filtered)

        params.append(
            FunctionParameter(
                name=param_name,
                type_name=type_name.strip(),
                data_location=data_location,
            )
        )
    return params


def _parse_structs(
    contract_clean: str,
    contract_offset: int,
    full_clean_source: str,
) -> tuple[list[StructDefinition], list[tuple[int, int]]]:
    """Extract `struct` definitions inside a contract and return their byte spans."""
    structs: list[StructDefinition] = []
    spans: list[tuple[int, int]] = []

    for match in _STRUCT_HEADER_RE.finditer(contract_clean):
        struct_name = match.group(1)
        rel_start = match.start()
        open_brace = match.end() - 1
        close_brace = _find_matching_brace(contract_clean, open_brace)
        spans.append((rel_start, close_brace + 1))

        abs_start = contract_offset + rel_start
        abs_end = contract_offset + close_brace
        struct_line = _line_number_at(full_clean_source, abs_start)
        struct_end_line = _line_number_at(full_clean_source, abs_end)

        body_str = contract_clean[open_brace + 1 : close_brace]
        body_abs_offset = contract_offset + open_brace + 1

        fields: list[StructField] = []
        semi_pos = 0
        for decl_match in re.finditer(r"([^;]+);", body_str):
            decl_text = " ".join(decl_match.group(1).strip().split())
            if not decl_text:
                continue
            tokens = decl_text.split()
            if len(tokens) < 2:
                continue
            field_name = tokens[-1]
            field_type = " ".join(tokens[:-1])
            field_abs = body_abs_offset + decl_match.start(1)
            field_line = _line_number_at(full_clean_source, field_abs)
            field_col = _column_at(full_clean_source, field_abs)
            byte_size = evm_type_bytes(field_type)
            fields.append(
                StructField(
                    name=field_name,
                    type_name=field_type,
                    byte_size=byte_size,
                    line=field_line,
                    column=field_col,
                )
            )
            semi_pos = decl_match.end()
        _ = semi_pos

        layout_items = [(f.name, f.type_name, f.byte_size, f.line) for f in fields]
        layout = compute_storage_layout(
            target_name=struct_name,
            kind="struct",
            line=struct_line,
            items=layout_items,
        )
        structs.append(
            StructDefinition(
                name=struct_name,
                line=struct_line,
                end_line=struct_end_line,
                fields=fields,
                storage_layout=layout,
            )
        )

    return structs, spans


def _parse_events(
    contract_clean: str,
    contract_offset: int,
    full_clean_source: str,
) -> list[EventDefinition]:
    """Extract `event` declarations inside a contract."""
    events: list[EventDefinition] = []
    for match in _EVENT_RE.finditer(contract_clean):
        event_name = match.group(1)
        params_raw = match.group(2)
        abs_start = contract_offset + match.start()
        line = _line_number_at(full_clean_source, abs_start)

        parameters: list[EventParameter] = []
        for part in _split_top_level_commas(params_raw):
            tokens = [tok for tok in part.split() if tok not in _DATA_LOCATIONS]
            if not tokens:
                continue
            indexed = "indexed" in tokens
            tokens_no_idx = [tok for tok in tokens if tok != "indexed"]
            if len(tokens_no_idx) >= 2:
                p_name = tokens_no_idx[-1]
                p_type = " ".join(tokens_no_idx[:-1])
            else:
                p_name = ""
                p_type = tokens_no_idx[0] if tokens_no_idx else ""
            parameters.append(
                EventParameter(
                    name=p_name,
                    type_name=p_type.strip(),
                    indexed=indexed,
                )
            )

        events.append(
            EventDefinition(
                name=event_name,
                line=line,
                parameters=parameters,
                raw_signature=" ".join(match.group(0).strip().split()),
            )
        )
    return events


def _parse_functions(
    contract_clean: str,
    contract_raw: str,
    contract_offset: int,
    full_clean_source: str,
) -> tuple[list[FunctionDefinition], list[tuple[int, int]]]:
    """Extract functions, constructors, receive, and fallback definitions."""
    functions: list[FunctionDefinition] = []
    spans: list[tuple[int, int]] = []

    for match in _FUNC_HEADER_RE.finditer(contract_clean):
        rel_start = match.start()
        if any(s <= rel_start < e for s, e in spans):
            continue

        if match.group(1) == "function":
            kind = "function"
            func_name = match.group(2)
        else:
            kind = match.group(3)
            func_name = kind

        open_paren = match.end() - 1
        close_paren = _find_matching_paren(contract_clean, open_paren)
        param_str = contract_clean[open_paren + 1 : close_paren]
        parameters = _parse_function_parameters(param_str)

        # Find either `{` (function body) or `;` (interface/unimplemented signature)
        cursor = close_paren + 1
        n = len(contract_clean)
        return_parameters: list[FunctionParameter] = []
        header_tail_tokens: list[str] = []

        # Scan from close_paren+1 to `{` or `;` at paren-depth 0
        depth = 0
        body_open_brace: int | None = None
        stmt_end: int = cursor
        i = cursor
        while i < n:
            ch = contract_clean[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif ch == "{" and depth == 0:
                body_open_brace = i
                break
            elif ch == ";" and depth == 0:
                stmt_end = i
                break
            i += 1

        header_end = body_open_brace if body_open_brace is not None else stmt_end
        header_suffix = contract_clean[close_paren + 1 : header_end]

        # Extract `returns (...)` if present
        returns_match = re.search(r"\breturns\s*\(", header_suffix)
        if returns_match:
            ret_open = close_paren + 1 + returns_match.end() - 1
            ret_close = _find_matching_paren(contract_clean, ret_open)
            return_parameters = _parse_function_parameters(
                contract_clean[ret_open + 1 : ret_close]
            )
            # Remove the returns(...) section before tokenizing modifiers/visibility
            rel_ret_start = returns_match.start()
            rel_ret_end = ret_close - (close_paren + 1) + 1
            header_suffix = (
                header_suffix[:rel_ret_start] + " " + header_suffix[rel_ret_end:]
            )

        # Remove modifier argument lists like `onlyRole(ADMIN_ROLE)` -> `onlyRole`
        cleaned_suffix = re.sub(r"\([^)]*\)", "", header_suffix)
        for tok in cleaned_suffix.split():
            tok_clean = tok.strip()
            if tok_clean and tok_clean not in {"virtual", "override"}:
                header_tail_tokens.append(tok_clean)

        visibility = "public" if kind == "constructor" else "external" if kind in {"receive", "fallback"} else "public"
        mutability = "nonpayable"
        modifiers: list[str] = []

        for tok in header_tail_tokens:
            if tok in _VISIBILITIES:
                visibility = tok
            elif tok in _MUTABILITIES:
                mutability = tok
            else:
                modifiers.append(tok)

        abs_start = contract_offset + rel_start
        start_line = _line_number_at(full_clean_source, abs_start)

        if body_open_brace is not None:
            body_close_brace = _find_matching_brace(contract_clean, body_open_brace)
            spans.append((rel_start, body_close_brace + 1))
            abs_end = contract_offset + body_close_brace
            end_line = _line_number_at(full_clean_source, abs_end)

            raw_body = contract_raw[body_open_brace + 1 : body_close_brace]
            clean_body = contract_clean[body_open_brace + 1 : body_close_brace]
            body_first_line = _line_number_at(
                full_clean_source, contract_offset + body_open_brace + 1
            )

            raw_lines = raw_body.splitlines()
            clean_lines = clean_body.splitlines()
            body_statements: list[StatementInfo] = []
            for offset_idx, (r_line, c_line) in enumerate(zip(raw_lines, clean_lines)):
                body_statements.append(
                    StatementInfo(
                        line=body_first_line + offset_idx,
                        raw=r_line,
                        stripped=c_line.strip(),
                    )
                )
        else:
            spans.append((rel_start, stmt_end + 1))
            abs_end = contract_offset + stmt_end
            end_line = _line_number_at(full_clean_source, abs_end)
            raw_body = ""
            body_statements = []

        functions.append(
            FunctionDefinition(
                name=func_name,
                kind=kind,
                visibility=visibility,
                mutability=mutability,
                modifiers=modifiers,
                parameters=parameters,
                return_parameters=return_parameters,
                line=start_line,
                end_line=end_line,
                body_lines=body_statements,
                raw_body=raw_body,
            )
        )

    return functions, spans


def _collect_other_block_spans(contract_clean: str) -> list[tuple[int, int]]:
    """Collect byte spans of modifier and enum blocks so their contents aren't parsed as state vars."""
    spans: list[tuple[int, int]] = []
    for regex in (_MODIFIER_BLOCK_RE, _ENUM_BLOCK_RE):
        for match in regex.finditer(contract_clean):
            open_brace = match.end() - 1
            close_brace = _find_matching_brace(contract_clean, open_brace)
            spans.append((match.start(), close_brace + 1))
    return spans


_IGNORED_STATE_PREFIXES = (
    "event ",
    "error ",
    "using ",
    "modifier ",
    "struct ",
    "enum ",
    "function ",
    "constructor",
    "receive",
    "fallback",
    "type ",
)


def _parse_state_variables(
    contract_clean: str,
    contract_offset: int,
    full_clean_source: str,
    excluded_spans: list[tuple[int, int]],
) -> list[StateVariable]:
    """Extract contract-level state variable declarations outside of functions/structs/modifiers."""
    chars = list(contract_clean)
    for start, end in excluded_spans:
        for idx in range(max(0, start), min(len(chars), end)):
            if chars[idx] != "\n":
                chars[idx] = " "
    masked = "".join(chars)

    # Strip the contract header up to its opening `{`
    first_brace = masked.find("{")
    last_brace = masked.rfind("}")
    if first_brace == -1 or last_brace == -1 or last_brace <= first_brace:
        return []

    interior = masked[first_brace + 1 : last_brace]
    interior_offset = contract_offset + first_brace + 1

    state_vars: list[StateVariable] = []
    for match in re.finditer(r"([^;{}]+);", interior):
        raw_decl = match.group(1)
        decl = " ".join(raw_decl.strip().split())
        if not decl or decl.startswith(_IGNORED_STATE_PREFIXES):
            continue

        # Strip initializer `= ...` without splitting `mapping(K => V)`
        lhs = re.split(r"=(?!>)", decl, maxsplit=1)[0].strip()
        if not lhs:
            continue

        # Handle mapping types where spaces may appear inside `mapping(a => b)`
        mapping_match = re.match(r"^(mapping\s*\([^)]+\)(?:\[\])*)\s+(.+)$", lhs)
        if mapping_match:
            type_name = " ".join(mapping_match.group(1).split())
            rest_tokens = mapping_match.group(2).split()
        else:
            tokens = lhs.split()
            if len(tokens) < 2:
                continue
            type_name = tokens[0]
            rest_tokens = tokens[1:]
            if type_name == "address" and rest_tokens and rest_tokens[0] == "payable":
                type_name = "address payable"
                rest_tokens = rest_tokens[1:]

        if not rest_tokens:
            continue

        var_name = rest_tokens[-1]
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", var_name):
            continue

        qualifiers = set(rest_tokens[:-1])
        visibility = "internal"
        for vis in _VISIBILITIES:
            if vis in qualifiers:
                visibility = vis
                break

        is_constant = "constant" in qualifiers
        is_immutable = "immutable" in qualifiers

        # Find offset of the declaration start
        non_ws_offset = match.start(1) + (len(raw_decl) - len(raw_decl.lstrip()))
        abs_pos = interior_offset + non_ws_offset
        line = _line_number_at(full_clean_source, abs_pos)
        col = _column_at(full_clean_source, abs_pos)
        byte_size = evm_type_bytes(type_name)

        state_vars.append(
            StateVariable(
                name=var_name,
                type_name=type_name,
                visibility=visibility,
                is_constant=is_constant,
                is_immutable=is_immutable,
                line=line,
                column=col,
                byte_size=byte_size,
            )
        )

    return state_vars


class SolidityParser:
    """Tokenizer and structural AST analyzer for Solidity source files."""

    def parse_source(
        self,
        source: str,
        file_path: str = "<memory>",
    ) -> list[ParsedContract]:
        clean_source = strip_comments_preserving_layout(source)
        pragmas = parse_pragmas(clean_source)
        suppressions = extract_suppressions(source)
        contracts: list[ParsedContract] = []

        for match in _CONTRACT_HEADER_RE.finditer(clean_source):
            kind = " ".join(match.group(1).split())
            name = match.group(2)
            inheritance_raw = match.group(3) or ""
            base_contracts = [
                base.strip()
                for base in _split_top_level_commas(inheritance_raw)
                if base.strip()
            ]

            start_idx = match.start()
            open_brace_idx = match.end() - 1
            close_brace_idx = _find_matching_brace(clean_source, open_brace_idx)

            contract_clean = clean_source[start_idx : close_brace_idx + 1]
            contract_raw = source[start_idx : close_brace_idx + 1]

            start_line = _line_number_at(clean_source, start_idx)
            end_line = _line_number_at(clean_source, close_brace_idx)

            structs, struct_spans = _parse_structs(
                contract_clean, start_idx, clean_source
            )
            events = _parse_events(contract_clean, start_idx, clean_source)
            functions, func_spans = _parse_functions(
                contract_clean, contract_raw, start_idx, clean_source
            )
            other_spans = _collect_other_block_spans(contract_clean)
            all_excluded = struct_spans + func_spans + other_spans

            state_variables = _parse_state_variables(
                contract_clean, start_idx, clean_source, all_excluded
            )

            # Compute EVM storage layout for persistent state variables
            persistent_vars = [
                v for v in state_variables if not v.is_constant and not v.is_immutable
            ]
            layout_items = [
                (v.name, v.type_name, v.byte_size, v.line) for v in persistent_vars
            ]
            storage_layout = compute_storage_layout(
                target_name=name,
                kind="contract",
                line=start_line,
                items=layout_items,
            )

            # Annotate slot_index and byte_offset back onto each StateVariable
            slot_lookup: dict[tuple[str, int], tuple[int, int]] = {}
            for slot in storage_layout.slots:
                for item in slot.items:
                    slot_lookup[(item.name, item.line)] = (
                        slot.slot_index,
                        item.byte_offset,
                    )

            for var in persistent_vars:
                coords = slot_lookup.get((var.name, var.line))
                if coords is not None:
                    var.slot_index, var.byte_offset = coords

            contracts.append(
                ParsedContract(
                    name=name,
                    kind=kind,
                    file_path=str(file_path),
                    line=start_line,
                    end_line=end_line,
                    base_contracts=base_contracts,
                    pragmas=pragmas,
                    state_variables=state_variables,
                    structs=structs,
                    events=events,
                    functions=functions,
                    storage_layout=storage_layout,
                    raw_source=source,
                    suppressed_lines=suppressions,
                )
            )

        return contracts

    def parse_file(self, path: str | Path) -> list[ParsedContract]:
        file_path = Path(path)
        content = file_path.read_text(encoding="utf-8")
        return self.parse_source(content, file_path=str(file_path))


def parse_solidity_source(
    source: str, file_path: str = "<memory>"
) -> list[ParsedContract]:
    """Convenience wrapper to parse a Solidity source string."""
    return SolidityParser().parse_source(source, file_path=file_path)


def parse_solidity_file(path: str | Path) -> list[ParsedContract]:
    """Convenience wrapper to parse a Solidity `.sol` file from disk."""
    return SolidityParser().parse_file(path)
