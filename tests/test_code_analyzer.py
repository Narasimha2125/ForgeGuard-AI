import tempfile
from pathlib import Path
from app.engines.code_analyzer import analyze_python_file, analyze_javascript_file

def test_ast_detects_long_function():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        # Create function with 70 lines
        lines = ["def massive_function():\n"]
        for i in range(70):
            lines.append(f"    x_{i} = {i}\n")
        lines.append("    return x_0\n")
        f.writelines(lines)
        temp_path = Path(f.name)

    try:
        findings = analyze_python_file(temp_path)
        long_func_findings = [item for item in findings if item["rule_id"] == "PY-LONG-FUNCTION"]
        assert len(long_func_findings) >= 1
        assert "massive_function" in long_func_findings[0]["title"]
    finally:
        temp_path.unlink()

def test_ast_detects_many_arguments():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write("def func_with_many_args(a, b, c, d, e, f, g, h):\n    pass\n")
        temp_path = Path(f.name)

    try:
        findings = analyze_python_file(temp_path)
        arg_findings = [item for item in findings if item["rule_id"] == "PY-EXCESSIVE-ARGS"]
        assert len(arg_findings) >= 1
    finally:
        temp_path.unlink()

def test_ast_detects_silent_exception_pass():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write("try:\n    x = 1 / 0\nexcept:\n    pass\n")
        temp_path = Path(f.name)

    try:
        findings = analyze_python_file(temp_path)
        suppressed = [item for item in findings if item["rule_id"] == "PY-SILENT-EXCEPTION"]
        assert len(suppressed) >= 1
    finally:
        temp_path.unlink()

def test_javascript_eval_detection():
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write("function compute(input) { return eval(input); }\n")
        temp_path = Path(f.name)

    try:
        findings = analyze_javascript_file(temp_path)
        eval_flaws = [item for item in findings if item["rule_id"] == "JS-EVAL-USE"]
        assert len(eval_flaws) >= 1
    finally:
        temp_path.unlink()
