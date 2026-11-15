"""Unit tests for SolidityParser, tokenizer, pragma inspector, and storage slot calculator."""

from __future__ import annotations

from pathlib import Path

from solguard.models import evm_type_bytes, is_packable_type
from solguard.parser import (
     extract_suppressions,
    parse_solidity_file,
    parse_solidity_source,
    strip_comments_preserving_layout,
)


def test_strip_comments_preserves_line_numbers() -> None:
    raw = (
        "// header comment\n"
        "pragma solidity ^0.8.20;\n"
        "/* multi\n"
        "   line\n"
        "   comment */\n"
        "contract Demo {\n"
        '    string public label = "// not a comment /* neither */";\n'
        "}\n"
    )
    cleaned = strip_comments_preserving_layout(raw)
    assert cleaned.count("\n") == raw.count("\n")
    assert "header comment" not in cleaned
    assert "multi" not in cleaned
    assert '"// not a comment /* neither */"' in cleaned


def test_extract_suppressions_directives() -> None:
    source = (
        "contract A {\n"
        "    // solguard-disable-next-line SG001, SG002\n"
        "    function foo() external {\n"
        "        target.call(\"\"); // solguard-disable-line SG001\n"
        "        // solguard-disable-next-line\n"
        "        other.call(\"\");\n"
        "    }\n"
        "}\n"
    )
    suppressions = extract_suppressions(source)
    assert suppressions[3] == {"SG001", "SG002"}
    assert suppressions[4] == {"SG001"}
    assert suppressions[6] == {"ALL"}


def test_evm_type_bytes_sizing() -> None:
    assert evm_type_bytes("bool") == 1
    assert evm_type_bytes("uint8") == 1
    assert evm_type_bytes("int16") == 2
    assert evm_type_bytes("uint64") == 8
    assert evm_type_bytes("uint128") == 16
    assert evm_type_bytes("address") == 20
    assert evm_type_bytes("address payable") == 20
    assert evm_type_bytes("bytes12") == 12
    assert evm_type_bytes("bytes32") == 32
    assert evm_type_bytes("uint256") == 32
    assert evm_type_bytes("uint") == 32
    assert evm_type_bytes("mapping(address => uint256)") == 32
    assert evm_type_bytes("uint256[]") == 32
    assert is_packable_type("uint128") is True
    assert is_packable_type("address") is True
    assert is_packable_type("uint256") is False
    assert is_packable_type("mapping(address => uint256)") is False


def test_parse_pragmas_floating_and_pinned() -> None:
    floating_src = "pragma solidity ^0.8.20;\ncontract A {}"
    pinned_src = "pragma solidity 0.8.20;\ncontract B {}"

    c_float = parse_solidity_source(floating_src)[0]
    c_pin = parse_solidity_source(pinned_src)[0]

    assert len(c_float.pragmas) == 1
    assert c_float.pragmas[0].is_floating is True
    assert c_float.pragmas[0].version_constraint == "^0.8.20"

    assert len(c_pin.pragmas) == 1
    assert c_pin.pragmas[0].is_floating is False
    assert c_pin.pragmas[0].version_constraint == "0.8.20"


def test_parse_state_variables_and_storage_slot_packing() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract StorageDemo {
        uint256 public constant MAX_SUPPLY = 1000;
        address public immutable deployer;
        uint128 public reserve0;
        uint128 public reserve1;
        uint256 public totalShares;
    }
    """
    contract = parse_solidity_source(source)[0]
    assert len(contract.state_variables) == 5

    # Only non-constant, non-immutable variables occupy EVM storage slots
    layout = contract.storage_layout
    assert layout.total_slots == 2
    assert layout.optimal_slots == 2
    assert layout.slots_saved == 0
    # reserve0 (16B) and reserve1 (16B) should share slot 0
    assert len(layout.slots[0].items) == 2
    assert layout.slots[0].used_bytes == 32
    assert layout.slots[0].items[0].name == "reserve0"
    assert layout.slots[0].items[0].byte_offset == 0
    assert layout.slots[0].items[1].name == "reserve1"
    assert layout.slots[0].items[1].byte_offset == 16
    assert layout.slots[1].items[0].name == "totalShares"


def test_suboptimal_struct_and_state_layout_detection(gas_inefficient_path: Path) -> None:
    contracts = parse_solidity_file(gas_inefficient_path)
    assert len(contracts) == 1
    contract = contracts[0]
    assert contract.name == "GasInefficientRegistry"

    # State variables: bool (1B), uint256 (32B), address (20B), uint64 (8B) + mapping (32B)
    # Sequential: Slot 0 [bool], Slot 1 [uint256], Slot 2 [address, uint64], Slot 3 [mapping] = 4 slots
    # Optimal: Slot 0 [uint256], Slot 1 [mapping], Slot 2 [address, uint64, bool] = 3 slots
    assert contract.storage_layout.total_slots == 4
    assert contract.storage_layout.optimal_slots == 3
    assert contract.storage_layout.slots_saved == 1
    assert contract.storage_layout.estimated_gas_saved == 22_100

    assert len(contract.structs) == 1
    order_struct = contract.structs[0]
    assert order_struct.name == "OrderRecord"
    assert order_struct.storage_layout.total_slots == 3
    assert order_struct.storage_layout.optimal_slots == 2
    assert order_struct.storage_layout.slots_saved == 1


def test_function_visibility_mutability_and_modifiers() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract Vault {
        function deposit(uint256[] calldata ids) external payable nonReentrant onlyOwner returns (bool ok) {
            ok = ids.length > 0;
        }
        function preview(uint256 x) public pure returns (uint256) {
            return x * 2;
        }
    }
    """
    contract = parse_solidity_source(source)[0]
    assert len(contract.functions) == 2

    dep = contract.functions[0]
    assert dep.name == "deposit"
    assert dep.visibility == "external"
    assert dep.mutability == "payable"
    assert "nonReentrant" in dep.modifiers
    assert "onlyOwner" in dep.modifiers
    assert dep.parameters[0].data_location == "calldata"
    assert dep.return_parameters[0].name == "ok"

    prev = contract.functions[1]
    assert prev.name == "preview"
    assert prev.visibility == "public"
    assert prev.mutability == "pure"
