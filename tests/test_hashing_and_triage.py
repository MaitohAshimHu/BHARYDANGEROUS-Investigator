"""Unit tests for hashing engine, file triage, entropy, and archive inspection."""
import pytest
from pathlib import Path

from bharydangerous.analyzers.archive_inspector import ArchiveInspector
from bharydangerous.analyzers.file_triage import calculate_entropy, triage_file
from bharydangerous.analyzers.strings_extractor import extract_strings
from bharydangerous.core.hashing import compute_hashes, verify_file_hashes

def test_hashing_and_tamper_detection(tmp_path: Path):
    test_file = tmp_path / "evidence.raw"
    test_file.write_bytes(b"Forensic Evidence Payload 1234567890")

    sha256, md5 = compute_hashes(test_file)
    assert len(sha256) == 64
    assert len(md5) == 32

    # Verification should succeed initially
    v_res = verify_file_hashes(test_file, sha256, md5)
    assert v_res["sha256_match"] is True
    assert v_res["md5_match"] is True

    # Tampering: modify 1 byte
    test_file.write_bytes(b"Forensic Evidence Payload 1234567891")
    v_tampered = verify_file_hashes(test_file, sha256, md5)
    assert v_tampered["sha256_match"] is False
    assert v_tampered["md5_match"] is False

def test_entropy_calculation():
    # Low entropy: repeated bytes
    low_data = b"AAAAAAAAAAAAAAAAAAAA" * 100
    low_ent = calculate_entropy(low_data)
    assert low_ent == 0.0

    # High entropy: all byte values equally distributed
    high_data = bytes(range(256)) * 10
    high_ent = calculate_entropy(high_data)
    assert 7.9 < high_ent <= 8.0

def test_file_triage(tmp_path: Path):
    sample = tmp_path / "script.sh"
    sample.write_text("#!/bin/bash\necho 'hello forensics'", encoding="utf-8")

    res = triage_file(sample)
    assert res["file_name"] == "script.sh"
    assert res["mime_type"] == "text/x-shellscript"
    assert res["is_executable"] is True
    assert len(res["sha256"]) == 64

def test_archive_inspection_safe_and_bomb(synthetic_safe_zip: Path, synthetic_bomb_zip: Path):
    insp = ArchiveInspector()

    # Safe archive
    safe_res = insp.inspect_archive(synthetic_safe_zip)
    assert safe_res["valid"] is True
    assert safe_res["format"] == "ZIP"
    assert safe_res["entry_count"] == 2
    assert safe_res["is_bomb_suspect"] is False

    # Bomb suspect archive
    bomb_res = insp.inspect_archive(synthetic_bomb_zip)
    assert bomb_res["valid"] is True
    assert bomb_res["is_bomb_suspect"] is True
    assert any("bomb" in w.lower() for w in bomb_res["warnings"])

def test_strings_and_ioc_extraction(tmp_path: Path):
    f = tmp_path / "sample.bin"
    content = b"garbage\x00http://c2-server.evil.com/payload.exe\x00198.51.100.42\x00garbage"
    f.write_bytes(content)

    res = extract_strings(f, min_length=4)
    assert res["total_extracted"] > 0
    iocs = res["iocs"]
    assert "198.51.100.42" in iocs["ips"]
    assert any("c2-server.evil.com" in url for url in iocs["urls"])
