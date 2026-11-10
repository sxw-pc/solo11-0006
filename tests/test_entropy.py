from __future__ import annotations
import base64
import hashlib
from shellhunt.engine.entropy import analyze_entropy, shannon_entropy
HIGH = base64.b64encode(hashlib.sha512(b"entropy-test-payload").digest()).decode()
def test_shannon_entropy_low_and_high():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0
    assert shannon_entropy(HIGH) > shannon_entropy("abababababababab")
def test_high_entropy_payload_is_extracted():
    source = f"<?php\n$blob = '{HIGH}';\n"
    report = analyze_entropy(source)
    assert report.suspicious_count >= 1
    assert report.payloads
    assert report.payloads[0]["entropy"] >= 4.2
    assert len(report.payloads[0]["preview"]) <= 67
def test_plain_text_has_no_payloads():
    report = analyze_entropy("<?php echo 'plain text';")
    assert report.suspicious_count == 0
    assert report.payloads == []
def test_nested_encoding_chain_depth():
    source = "<?php $x = base64_decode(str_rot13(gzinflate($blob)));"
    report = analyze_entropy(source)
    assert report.encoding_depth == 3
    assert report.encoding_functions == ["base64_decode", "gzinflate", "str_rot13"]
def test_single_decoder_depth_and_no_decoder():
    assert analyze_entropy("<?php base64_decode($x);").encoding_depth == 1
    report = analyze_entropy("<?php echo strlen($x);")
    assert report.encoding_depth == 0
    assert report.encoding_functions == []
def test_longest_token_and_overall_entropy():
    source = "<?php $x = 'abcdefghijklmnop';"
    report = analyze_entropy(source)
    assert report.overall > 0
    assert report.longest_length >= len("abcdefghijklmnop")
    assert report.longest_entropy > 0
def test_entropy_dict_contract():
    data = analyze_entropy(f"<?php $x = '{HIGH}';").as_dict()
    assert set(data) >= {
        "overall",
        "longest_length",
        "longest_entropy",
        "suspicious_count",
        "payloads",
        "encoding_depth",
        "encoding_functions",
    }
    assert isinstance(data["payloads"], list)
