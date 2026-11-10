from __future__ import annotations
from shellhunt.engine.features import analyze_features
from shellhunt.engine.tokenizer import tokenize
EVAL = "ev" + "al"
SYSTEM = "sys" + "tem"
POST = "$_" + "POST"
GET = "$_" + "GET"
def php(body: str) -> str:
    return "<?php\n" + body + "\n"
def test_dynamic_call_with_request_is_detected():
    source = php(f"$fn({GET}['action']);")
    report = analyze_features(source)
    assert report.signal("dynamic_call").score > 0
    assert report.signal("dynamic_call").lines == [2]
    assert report.signal("direct_input").score > 0
    assert report.superglobal_lines == [2]
def test_dynamic_call_without_request_is_quiet():
    report = analyze_features(php("$fn($safeArgument);"))
    assert report.signal("dynamic_call").score == 0
    assert report.signal("direct_input").score == 0
def test_direct_execution_of_post_data():
    report = analyze_features(php(f"{EVAL}({POST}['code']);"))
    assert report.signal("dangerous_calls").score > 0
    assert report.signal("direct_input").score > 0
    assert report.signal("direct_input").lines == [2]
    assert EVAL in report.dangerous_functions
def test_direct_input_negative_when_argument_is_safe():
    report = analyze_features(php(f"{EVAL}($expressionFromConfig);"))
    assert report.signal("dangerous_calls").score > 0
    assert report.signal("direct_input").score == 0
def test_include_request_is_direct_input():
    report = analyze_features(php(f"include {GET}['page'];"))
    assert report.signal("direct_input").score > 0
    assert 2 in report.signal("direct_input").lines
def test_file_sink_with_request_is_direct_input():
    source = php(f"file_put_contents($path, {POST}['body']);")
    report = analyze_features(source)
    assert report.signal("direct_input").score > 0
    assert report.signal("direct_input").lines == [2]
def test_comments_and_strings_are_not_calls():
    source = php(f"// {EVAL}({POST}['x']);\n$s = '{SYSTEM}({GET}[x])';")
    report = analyze_features(source)
    assert report.signal("dangerous_calls").score == 0
    assert report.dangerous_functions == {}
def test_method_calls_are_not_function_calls():
    report = analyze_features(php(f"$obj->{SYSTEM}({GET}['x']);"))
    assert report.signal("dangerous_calls").score == 0
def test_obfuscation_signals_add_up():
    source = php(
        "$part = chr(65) . chr(66) . chr(67) . chr(68);\n"
        "$$dynamic = 1;\n"
        '$blob = "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48";'
    )
    report = analyze_features(source)
    assert report.signal("obfuscation").score > 0
    assert report.signal("obfuscation").lines
def test_plain_assignment_has_no_obfuscation():
    report = analyze_features(php("$total = $left + $right;"))
    assert report.signal("obfuscation").score == 0
def test_multiple_dangerous_functions_and_lines():
    source = php(f"{SYSTEM}($cmd);\npassthru($cmd);")
    report = analyze_features(source)
    assert set(report.dangerous_functions) >= {SYSTEM, "passthru"}
    assert report.signal("dangerous_calls").score >= 0.5
def test_report_is_json_friendly():
    data = analyze_features(php(f"{EVAL}({POST}['x']);")).as_dict()
    assert isinstance(data["signals"]["direct_input"]["lines"], list)
    assert data["signals"]["direct_input"]["score"] <= 1
    assert data["token_count"] > 0
def test_tokenizer_string_line_number_is_start_line():
    tokens = tokenize('<?php\n$s = "a\nb";\n')
    string = next(token for token in tokens if token.kind == "string")
    assert string.line == 2
