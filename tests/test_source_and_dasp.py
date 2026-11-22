from evalharness.dasp import slither_slug_to_dasp
from evalharness.source import function_at_line, pragma_constraint, sha256_bytes

SOURCE = 'pragma solidity ^0.5.0;\n\ncontract Vault {\n    function deposit() public payable {}\n\n    function withdraw() public {\n        msg.sender.call.value(address(this).balance)("");\n    }\n}\n'

def test_pragma_and_function_at_line():
    assert pragma_constraint(SOURCE) == '^0.5.0'
    lines = SOURCE.splitlines()
    wline = next(i for i, ln in enumerate(lines, 1) if 'function withdraw' in ln)
    assert function_at_line(SOURCE, wline) == 'withdraw'
    dline = next(i for i, ln in enumerate(lines, 1) if 'function deposit' in ln)
    assert function_at_line(SOURCE, dline) == 'deposit'

def test_sha256_stable():
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_dasp_slugs():
    assert slither_slug_to_dasp('reentrancy-eth') == 'reentrancy'
    assert slither_slug_to_dasp('timestamp') == 'time_manipulation'
    assert slither_slug_to_dasp('weak-prng') == 'bad_randomness'
    assert slither_slug_to_dasp('unchecked-lowlevel') == 'unchecked_low_level_calls'
    assert slither_slug_to_dasp('tx-origin') == 'access_control'
    assert slither_slug_to_dasp('totally-unknown-detector') == 'other'

