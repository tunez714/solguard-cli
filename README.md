# solguard-cli

**solguard-cli** is a fast, zero-dependency Python 3.11+ static analyzer and EVM 32-byte storage-slot gas linter for Solidity smart contracts. It inspects `.sol` source files and workspaces for high-impact security anti-patterns and storage/calldata gas inefficiencies, exporting human-readable terminal tables, structured JSON, and OASIS **SARIF v2.1.0** reports for CI/CD pipelines.

---

## Key Capabilities

- **Comment-Preserving Structural Tokenizer (`solguard.parser`)**: Strips single-line (`//`) and multi-line (`/* */`) comments while maintaining exact 1-indexed line and column offsets, extracting `pragma` constraints, `contract`/`library`/`interface` blocks, `struct` declarations, `event` signatures, state variables, and function bodies.
- **EVM 32-Byte Storage Slot Simulator (`solguard.parser` & `solguard.models`)**: Models sequential 256-bit EVM storage slot packing across persistent state variables and structs, then applies First-Fit Decreasing (FFD) bin packing to compute optimal variable ordering and estimate cold `SSTORE`/`SLOAD` gas savings (`22,100` gas per eliminated slot).
- **Modular Defensive Rule Engine (`solguard.rules`)**: Extensible `BaseRule` architecture covering low-level call verification, Checks-Effects-Interactions (CEI) reentrancy checks, authentication hygiene, event topic indexing, and `calldata` vs `memory` ABI optimizations.
- **Inline Suppression Directives**: Supports `// solguard-disable-next-line [RULE_ID]` and `// solguard-disable-line [RULE_ID]` comments for audited exceptions.
- **CI-Ready Exporters (`solguard.reporter`)**: Outputs terminal diagnostic tables (`text`), machine-readable `json`, and **SARIF v2.1.0** (`sarif`) compatible with GitHub Code Scanning.

---

## Built-In Rules

| Rule ID | Severity | Category | Title | Summary |
| :--- | :--- | :--- | :--- | :--- |
| `SG001` | `HIGH` | `security` | Unchecked Low-Level Call Return Value | Flags `.call()`, `.delegatecall()`, `.staticcall()`, and `.send()` invocations whose boolean return value is ignored. |
| `SG002` | `HIGH` | `security` | State Write After External Call (CEI Violation) | Flags contract storage mutations occurring after an external call in functions without a `nonReentrant` lock modifier. |
| `SG003` | `MEDIUM` | `security` | Dangerous `tx.origin` Authorization Check | Flags `tx.origin` usage inside `require()`, `if (...)`, or equality comparisons for access control. |
| `SG004` | `LOW` | `gas` | Unindexed Filterable Event Parameters | Flags `event` declarations with fewer than 3 `indexed` topics when filterable value types (`address`, `uint*`, `int*`, `bytes32`, `bool`) are left unindexed. |
| `SG005` | `MEDIUM` | `gas` | EVM Storage Packing & Calldata Gas Optimization | Flags structs and contract state variables that waste 32-byte EVM storage slots, plus `external` functions using `memory` instead of `calldata` for read-only reference parameters. |

---

## Installation

```bash
git clone https://github.com/tunez714/solguard-cli.git
cd solguard-cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## CLI Usage

### 1. Scan a Contract or Workspace

```bash
# Human-readable terminal report
solguard scan contracts/

# Filter by minimum severity and fail CI (exit code 1) on HIGH findings
solguard scan contracts/Vault.sol --severity medium --fail-on high

# Export SARIF v2.1.0 report for GitHub Code Scanning
solguard scan contracts/ --format sarif --output results.sarif

# Run specific rules only
solguard scan contracts/ --rule SG001 --rule SG005 --format json
```

### 2. Inspect EVM 32-Byte Storage Slot Packing

```bash
solguard layout tests/fixtures/gas_inefficient.sol
```

Example output:

```text
CONTRACT `GasInefficientRegistry` (line 4) — Current Slots: 4 | Optimal Slots: 3 | Potential Savings: 1 slot(s) (~22,100 gas)
------------------------------------------------------------------------------
SLOT   USED (B)   FREE (B)   PACKED VARIABLES (OFFSET: TYPE NAME [BYTES])
0      1          31         +0B: bool paused [1B]
1      32         0          +0B: uint256 protocolFeeBps [32B]
2      28         4          +0B: address treasury [20B], +20B: uint64 epoch [8B]
3      32         0          +0B: mapping(uint256 => OrderRecord) orders [32B]
```

### 3. List Available Rules

```bash
solguard rules
solguard rules --format json
```

---

## Inline Suppressions

Audited lines can suppress specific rules or all rules on the current or next line:

```solidity
// solguard-disable-next-line SG001
target.call{value: 0}("");

require(tx.origin == msg.sender, "EOA only"); // solguard-disable-line SG003
```

---

## Architecture

```text
src/solguard/
├── __init__.py       # Package metadata and version
├── __main__.py       # `python -m solguard` entrypoint
├── models.py         # AST dataclasses, Severity/Category enums, EVM byte-sizing math
├── parser.py         # Comment-preserving tokenizer, AST extractor, 32-byte slot packer
├── engine.py         # File discovery, rule orchestration, inline suppression filter
├── reporter.py       # Terminal table, JSON, and SARIF v2.1.0 formatters
├── cli.py            # Argument parser (`scan`, `layout`, `rules`) and exit-code handler
└── rules/
    ├── __init__.py   # Rule registry (`get_all_rules`, `get_rule_by_id`)
    ├── base.py       # Abstract `BaseRule` interface
    ├── security.py   # SG001 (unchecked calls), SG002 (CEI reentrancy), SG003 (tx.origin)
    └── gas.py        # SG004 (unindexed events), SG005 (storage packing & calldata)
```

---

## Running Tests

```bash
pytest -v
```

---

## Roadmap

- **C3 Inheritance Linearization**: Resolve cross-contract state variable shadowing, virtual/override modifiers, and inherited storage slot offsets across multi-file workspaces.
- **Foundry & Hardhat Workspace Discovery**: Parse `foundry.toml` and `remappings.txt` to resolve `@openzeppelin/` and external library imports automatically.
- **Declarative Configuration (`.solguard.yml`)**: Support per-directory rule severity overrides, custom ignore globs, and project-wide pragma policies.
- **Git-Diff Incremental Scanning**: Add `--changed-only` mode to lint only modified contracts and functions in pull requests.
- **Opcode-Level Storage Cost Estimator**: Model warm vs. cold `SLOAD`/`SSTORE` access patterns (EIP-2929) across hot execution paths.

---

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 tunez714.
