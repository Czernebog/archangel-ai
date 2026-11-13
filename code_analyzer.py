"""Read-only Python AST inspection. No imported source is executed."""
from __future__ import annotations
import ast
import re

MAX_CODE_LENGTH = 80_000

def analyze_python(source):
    if not isinstance(source, str) or not source.strip() or len(source) > MAX_CODE_LENGTH:
        raise ValueError('Вставь исходный код Python размером до 80 000 символов.')
    issues = []
    def add(level, line, message):
        if len(issues) < 80:
            issues.append({'level': level, 'line': line, 'message': message})
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        add('error', exc.lineno or 1, f'Синтаксическая ошибка: {exc.msg} (столбец {exc.offset or 1})')
        return {'ok': False, 'language': 'Python', 'lines': source.count('\n') + 1,
                'issues': issues, 'functions': 0, 'classes': 0,
                'note': 'Разбор исходного кода без выполнения.'}
    except (ValueError, MemoryError, RecursionError):
        raise ValueError('Код слишком сложен для безопасного синтаксического анализа.') from None

    functions = sum(isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) for x in ast.walk(tree))
    classes = sum(isinstance(x, ast.ClassDef) for x in ast.walk(tree))
    for node in ast.walk(tree):
        line = getattr(node, 'lineno', 1)
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            add('warning', line, 'Слишком широкий except: обработка ошибок может скрывать сбои.')
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in ('eval', 'exec'):
                add('warning', line, 'Динамическое выполнение кода требует особой проверки входных данных.')
            if isinstance(func, ast.Attribute) and func.attr in ('run', 'Popen', 'call') and isinstance(func.value, ast.Name) and func.value.id == 'subprocess':
                if any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                    add('warning', line, 'subprocess с shell=True: исключи подстановку недоверенного ввода.')
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 12:
                for target in targets:
                    if isinstance(target, ast.Name) and re.search(r'(api[_]?key|secret|password|token)', target.id, re.I):
                        add('warning', line, 'Возможный секрет в исходном коде: используй переменную окружения.')
                        break
    return {'ok': True, 'language': 'Python', 'lines': source.count('\n') + 1,
            'functions': functions, 'classes': classes, 'issues': issues,
            'note': 'Проверка AST выполнена без запуска программы; тесты и аудит безопасности не выполнялись.'}
