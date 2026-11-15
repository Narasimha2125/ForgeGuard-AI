import ast
import re
from pathlib import Path
try:
    from radon.complexity import cc_visit
    from radon.metrics import mi_visit
    RADON_AVAILABLE = True
except ImportError:
    RADON_AVAILABLE = False


def extract_code_snippet(lines, line_number, context=2):
    if not lines or not line_number or line_number < 1 or line_number > len(lines):
        return ""
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    snippet_lines = []
    for idx in range(start, end):
        prefix = "-> " if idx + 1 == line_number else "   "
        snippet_lines.append(f"{prefix}{idx + 1:4d} | {lines[idx]}")
    return "\n".join(snippet_lines)


def analyze_python_file(path: Path, root_path: Path = None):
    findings = []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        lines = source.splitlines()
    except Exception as exc:
        return [{
            "rule_id": "PY-READ-ERR",
            "category": "code_quality",
            "severity": "medium",
            "confidence": "high",
            "line_number": 1,
            "column_number": 1,
            "code_snippet": "",
            "title": "Unreadable File",
            "description": f"Could not read file {path.name}: {str(exc)}",
            "technical_explanation": "File I/O error occurred during inspection.",
            "why_it_matters": "The file cannot be verified for quality and security compliance.",
            "recommendation": "Check file permissions and UTF-8 encoding.",
            "suggested_fix": "Save file with standard UTF-8 encoding.",
            "detection_tool": "ForgeGuard Core"
        }]

    # 1. AST Parsing & Syntax validation
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        snippet = extract_code_snippet(lines, exc.lineno or 1)
        return [{
            "rule_id": "PY-SYNTAX-ERR",
            "category": "code_quality",
            "severity": "high",
            "confidence": "high",
            "line_number": exc.lineno or 1,
            "column_number": exc.offset or 1,
            "code_snippet": snippet,
            "title": f"Syntax Error: {exc.msg}",
            "description": f"Python interpreter syntax error at line {exc.lineno}: {exc.msg}",
            "technical_explanation": f"The parser failed with {exc.__class__.__name__}: {exc.msg}. Code cannot be executed in this state.",
            "why_it_matters": "Syntax errors crash the runtime and indicate broken build or incomplete commits.",
            "recommendation": "Correct the syntax error according to Python grammar specifications.",
            "suggested_fix": f"Review line {exc.lineno} and surrounding statements.",
            "detection_tool": "Python AST Parser"
        }]

    # 2. Radon Cyclomatic Complexity & Maintainability Index
    if RADON_AVAILABLE:
        try:
            complexity_blocks = cc_visit(source)
            for block in complexity_blocks:
                if block.complexity >= 10:
                    sev = "high" if block.complexity >= 15 else "medium"
                    snippet = extract_code_snippet(lines, block.lineno)
                    findings.append({
                        "rule_id": "PY-HIGH-COMPLEXITY",
                        "category": "code_quality",
                        "severity": sev,
                        "confidence": "high",
                        "line_number": block.lineno,
                        "column_number": getattr(block, "col_offset", 1),
                        "code_snippet": snippet,
                        "title": f"High Cyclomatic Complexity: {block.name} (CC={block.complexity})",
                        "description": f"Function or method '{block.name}' has a cyclomatic complexity of {block.complexity} (grade {block.letter}).",
                        "technical_explanation": "Cyclomatic complexity measures the number of linearly independent paths through program source code.",
                        "why_it_matters": "High complexity dramatically increases defect probability, slows down refactoring, and requires more unit tests.",
                        "recommendation": "Decompose into smaller helper functions and reduce conditional branching.",
                        "suggested_fix": "Extract sub-branches into cohesive helper functions.",
                        "detection_tool": "Radon Complexity Engine"
                    })
        except Exception:
            pass

        try:
            mi_score = mi_visit(source, multi=True)
            if mi_score < 40:
                findings.append({
                    "rule_id": "PY-POOR-MAINTAINABILITY",
                    "category": "code_quality",
                    "severity": "medium",
                    "confidence": "high",
                    "line_number": 1,
                    "column_number": 1,
                    "code_snippet": extract_code_snippet(lines, 1),
                    "title": f"Low Maintainability Index ({round(mi_score, 1)}/100)",
                    "description": f"File maintainability index is {round(mi_score, 1)}, indicating difficult maintenance.",
                    "technical_explanation": "Maintainability Index is calculated from Halstead volume, Cyclomatic Complexity, and SLOC.",
                    "why_it_matters": "Low maintainability correlates with higher maintenance costs and regression frequency.",
                    "recommendation": "Refactor complex methods, reduce SLOC, and improve documentation.",
                    "suggested_fix": "Break monolithic logic into modular components.",
                    "detection_tool": "Radon MI Engine"
                })
        except Exception:
            pass

    # 3. AST Structural & Code Smell Checks
    imported_names = set()
    used_names = set()

    for node in ast.walk(tree):
        # Collect imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add((alias.asname or alias.name, node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported_names.add((alias.asname or alias.name, node.lineno, f"{node.module}.{alias.name}"))
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                used_names.add(node.id)

        # Long functions & Many arguments
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            span = (node.end_lineno - node.lineno + 1) if (node.end_lineno and node.lineno) else 0
            if span > 60:
                snippet = extract_code_snippet(lines, node.lineno)
                findings.append({
                    "rule_id": "PY-LONG-FUNCTION",
                    "category": "code_quality",
                    "severity": "medium",
                    "confidence": "high",
                    "line_number": node.lineno,
                    "column_number": node.col_offset + 1,
                    "code_snippet": snippet,
                    "title": f"Excessively Long Function: '{node.name}' ({span} lines)",
                    "description": f"Function '{node.name}' spans {span} lines. Ideal functions should adhere to the Single Responsibility Principle.",
                    "technical_explanation": "Functions exceeding 50-60 lines typically violate separation of concerns and accumulate unintended side effects.",
                    "why_it_matters": "Long functions are difficult to comprehend, verify with unit tests, and maintain.",
                    "recommendation": "Decompose into smaller helper functions with clear responsibilities.",
                    "suggested_fix": f"# Extract helper functions from {node.name}\ndef process_step(data):\n    pass",
                    "detection_tool": "Python AST Analyzer"
                })

            pos_args = len(node.args.args)
            if pos_args > 6:
                snippet = extract_code_snippet(lines, node.lineno)
                findings.append({
                    "rule_id": "PY-EXCESSIVE-ARGS",
                    "category": "code_quality",
                    "severity": "low",
                    "confidence": "medium",
                    "line_number": node.lineno,
                    "column_number": node.col_offset + 1,
                    "code_snippet": snippet,
                    "title": f"Excessive Function Arguments: '{node.name}' ({pos_args} params)",
                    "description": f"Function '{node.name}' accepts {pos_args} positional parameters.",
                    "technical_explanation": "Functions with high arity create tight coupling and increase caller-side invocation errors.",
                    "why_it_matters": "Makes calling and refactoring error-prone; callers easily transpose arguments.",
                    "recommendation": "Group related arguments into a dataclass, Pydantic model, or kwargs dictionary.",
                    "suggested_fix": f"from dataclasses import dataclass\n@dataclass\nclass {node.name.capitalize()}Params:\n    # define fields here",
                    "detection_tool": "Python AST Analyzer"
                })

            # Check for docstrings in public functions
            if not node.name.startswith("_") and not ast.get_docstring(node):
                snippet = extract_code_snippet(lines, node.lineno)
                findings.append({
                    "rule_id": "PY-MISSING-DOCSTRING",
                    "category": "code_quality",
                    "severity": "info",
                    "confidence": "high",
                    "line_number": node.lineno,
                    "column_number": node.col_offset + 1,
                    "code_snippet": snippet,
                    "title": f"Missing Docstring in Public Function: '{node.name}'",
                    "description": f"Public function '{node.name}' has no docstring explaining parameters and return values.",
                    "technical_explanation": "PEP 257 mandates docstrings for all public modules, functions, classes, and methods.",
                    "why_it_matters": "Impedes API readability, IDE tooltips, and automatic documentation generation.",
                    "recommendation": "Add a descriptive docstring documenting purpose, args, and returns.",
                    "suggested_fix": f'"""Brief summary of {node.name}.\n\nArgs:\n    ...\nReturns:\n    ...\n"""',
                    "detection_tool": "Python AST Analyzer"
                })

        # Deep Nesting check
        if isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            nesting_level = 0
            curr = node
            # Count parents that are control flow blocks
            # We can approximate nesting by indentation:
            if hasattr(node, "col_offset"):
                nesting_level = node.col_offset // 4
            if nesting_level >= 5:
                snippet = extract_code_snippet(lines, node.lineno)
                findings.append({
                    "rule_id": "PY-DEEP-NESTING",
                    "category": "code_quality",
                    "severity": "medium",
                    "confidence": "medium",
                    "line_number": node.lineno,
                    "column_number": node.col_offset + 1,
                    "code_snippet": snippet,
                    "title": f"Deep Control Flow Nesting (Level {nesting_level})",
                    "description": f"Control block is indented {nesting_level} levels deep.",
                    "technical_explanation": "Deeply nested code exhibits high cognitive complexity and 'arrow anti-pattern'.",
                    "why_it_matters": "Hard to follow code branches and verify all edge conditions.",
                    "recommendation": "Use early return/guard clauses or extract inner blocks into separate functions.",
                    "suggested_fix": "if not condition:\n    return\n# proceed without nesting",
                    "detection_tool": "Python AST Analyzer"
                })

        # Bare except or except pass
        if isinstance(node, ast.ExceptHandler):
            is_bare = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in ("BaseException", "Exception"))
            has_only_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
            if has_only_pass:
                snippet = extract_code_snippet(lines, node.lineno)
                findings.append({
                    "rule_id": "PY-SILENT-EXCEPTION",
                    "category": "code_quality",
                    "severity": "high",
                    "confidence": "high",
                    "line_number": node.lineno,
                    "column_number": node.col_offset + 1,
                    "code_snippet": snippet,
                    "title": "Exception Silently Suppressed (except: pass)",
                    "description": "An exception handler catches exceptions and silently discards them with 'pass'.",
                    "technical_explanation": "Silent exception suppression blinds operators to unexpected errors and masks bugs.",
                    "why_it_matters": "Bugs, timeouts, and data corruption pass unnoticed into later system stages.",
                    "recommendation": "Log the exception with traceback or raise a domain-specific exception.",
                    "suggested_fix": "except Exception as exc:\n    logger.error('Operation failed: %s', exc, exc_info=True)",
                    "detection_tool": "Python AST Analyzer"
                })
            elif is_bare and node.type is None:
                snippet = extract_code_snippet(lines, node.lineno)
                findings.append({
                    "rule_id": "PY-BARE-EXCEPT",
                    "category": "code_quality",
                    "severity": "medium",
                    "confidence": "high",
                    "line_number": node.lineno,
                    "column_number": node.col_offset + 1,
                    "code_snippet": snippet,
                    "title": "Bare 'except:' Clause",
                    "description": "A bare 'except:' clause intercepts SystemExit and KeyboardInterrupt as well.",
                    "technical_explanation": "PEP 8 discourages bare except because it catches signals that terminate scripts.",
                    "why_it_matters": "Prevents normal process shutdown, Ctrl+C cancellation, and hides syntax errors.",
                    "recommendation": "Specify concrete exception types or catch 'Exception'.",
                    "suggested_fix": "except SpecificError as exc:",
                    "detection_tool": "Python AST Analyzer"
                })

    # Check for unused imports (heuristic check)
    for name, lineno, full_path in imported_names:
        if name not in used_names and not name.startswith("_") and name != "*":
            # skip __all__ references or common dunder files
            if path.name == "__init__.py":
                continue
            snippet = extract_code_snippet(lines, lineno)
            findings.append({
                "rule_id": "PY-UNUSED-IMPORT",
                "category": "code_quality",
                "severity": "low",
                "confidence": "medium",
                "line_number": lineno,
                "column_number": 1,
                "code_snippet": snippet,
                "title": f"Unused Import: '{name}'",
                "description": f"Imported module or symbol '{name}' is never referenced in this file.",
                "technical_explanation": "Unused imports clutter the namespace and slow module load time.",
                "why_it_matters": "Increases cognitive overhead, startup latency, and can trigger unwanted side effects.",
                "recommendation": "Remove unused import.",
                "suggested_fix": f"# Remove line: import / from ... import {name}",
                "detection_tool": "Python AST Analyzer"
            })

    return findings


def analyze_javascript_file(path: Path):
    findings = []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        lines = source.splitlines()
    except Exception:
        return []

    # JS/TS checks using regex pattern scanning
    patterns = [
        (
            r"\beval\s*\(",
            "JS-EVAL-USE",
            "high",
            "Dangerous eval() In JavaScript",
            "The eval() function compiles and executes arbitrary strings as JavaScript code.",
            "Enables Cross-Site Scripting (XSS) and arbitrary script execution if supplied user input.",
            "Replace eval() with JSON.parse() or structured logic.",
            "JSON.parse(data)"
        ),
        (
            r"document\.write\s*\(",
            "JS-DOC-WRITE",
            "medium",
            "Use of document.write()",
            "document.write() writes directly into the DOM stream and can overwrite entire documents.",
            "Slows page load performance and introduces DOM-based XSS vulnerabilities.",
            "Use standard DOM manipulation methods such as document.createElement() or textContent.",
            "element.textContent = data;"
        ),
        (
            r"\.innerHTML\s*=",
            "JS-INNER-HTML",
            "medium",
            "Potential DOM XSS via innerHTML Assignment",
            "Assigning unescaped strings directly to innerHTML parses raw HTML.",
            "Allows malicious attackers to inject script tags or event handlers (DOM XSS).",
            "Use textContent, innerText, or sanitize HTML before insertion using DOMPurify.",
            "element.textContent = sanitizedValue;"
        ),
        (
            r"==(?!=)",
            "JS-LOOSE-EQUALITY",
            "low",
            "Loose Equality (==) Operator Used",
            "Loose equality performs implicit type coercion which frequently causes unexpected bugs.",
            "Type coercion in JS leads to unexpected edge case evaluations like ('0' == false).",
            "Use strict equality (===) and strict inequality (!==).",
            "if (a === b)"
        ),
        (
            r"console\.log\s*\(",
            "JS-CONSOLE-LOG",
            "info",
            "Console Logging in Production Code",
            "console.log statements left in frontend code leak debugging details to the browser console.",
            "Can inadvertently expose sensitive state or customer data to anyone inspecting DevTools.",
            "Remove debug log statements or wrap them in an environment debug flag.",
            "// remove before production"
        )
    ]

    for idx, line in enumerate(lines):
        for pattern, rule_id, sev, title, tech_exp, why_matters, rec, fix in patterns:
            if re.search(pattern, line):
                findings.append({
                    "rule_id": rule_id,
                    "category": "code_quality",
                    "severity": sev,
                    "confidence": "medium",
                    "line_number": idx + 1,
                    "column_number": 1,
                    "code_snippet": extract_code_snippet(lines, idx + 1),
                    "title": title,
                    "description": f"Pattern detected: {line.strip()}",
                    "technical_explanation": tech_exp,
                    "why_it_matters": why_matters,
                    "recommendation": rec,
                    "suggested_fix": fix,
                    "detection_tool": "ForgeGuard JS Scanner"
                })

    return findings


def analyze_generic_source_file(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".py":
        return analyze_python_file(path)
    elif suffix in (".js", ".jsx", ".ts", ".tsx"):
        return analyze_javascript_file(path)
    return []
