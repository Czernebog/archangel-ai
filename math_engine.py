"""ARCHANGEL symbolic math: bounded AST, no eval or unsafe sympify."""
import ast
import re

MAX_EXPRESSION = 180
VARIABLES = ('x', 'y', 'z', 't')

def calculate(query, operation='simplify', variable='x'):
    import sympy as sp
    if not isinstance(query, str) or not query.strip() or len(query) > MAX_EXPRESSION:
        raise ValueError('Выражение пустое или длиннее 180 символов.')
    if operation not in {'simplify', 'solve', 'diff', 'integrate', 'factor'}:
        raise ValueError('Неизвестная математическая операция.')
    if variable not in VARIABLES:
        raise ValueError('Выбери переменную x, y, z или t.')
    symbols = {v: sp.Symbol(v, real=True) for v in VARIABLES}
    constants = {**symbols, 'pi': sp.pi, 'e': sp.E}
    functions = {'sqrt':sp.sqrt, 'sin':sp.sin, 'cos':sp.cos, 'tan':sp.tan,
                 'asin':sp.asin, 'acos':sp.acos, 'atan':sp.atan, 'abs':sp.Abs,
                 'ln':sp.log, 'log':sp.log, 'exp':sp.exp}
    def parse(raw):
        raw = raw.strip().replace('^','**').replace('−','-').replace('×','*').replace('÷','/').replace('π','pi')
        raw = re.sub(r'(?<=\d)(?=[xyzt]\b)', '*', raw)
        if len(raw)>MAX_EXPRESSION: raise ValueError('Выражение слишком длинное.')
        try: tree=ast.parse(raw,mode='eval')
        except SyntaxError as exc: raise ValueError('Неверный синтаксис. Пример: x^2-5*x+6=0.') from exc
        if sum(1 for _ in ast.walk(tree))>80: raise ValueError('Слишком сложное выражение.')
        def visit(node, depth=0):
            if depth>24: raise ValueError('Слишком много вложенных скобок.')
            if isinstance(node,ast.Constant) and type(node.value) in (int,float):
                if abs(node.value)>1e12: raise ValueError('Слишком большое число.')
                return sp.Integer(node.value) if type(node.value) is int else sp.Rational(str(node.value))
            if isinstance(node,ast.Name) and node.id in constants: return constants[node.id]
            if isinstance(node,ast.UnaryOp) and isinstance(node.op,(ast.USub,ast.UAdd)):
                v=visit(node.operand,depth+1)
                return -v if isinstance(node.op,ast.USub) else v
            if isinstance(node,ast.BinOp) and isinstance(node.op,(ast.Add,ast.Sub,ast.Mult,ast.Div,ast.Pow)):
                a=visit(node.left,depth+1);b=visit(node.right,depth+1)
                if isinstance(node.op,ast.Add): return a+b
                if isinstance(node.op,ast.Sub): return a-b
                if isinstance(node.op,ast.Mult): return a*b
                if isinstance(node.op,ast.Div):
                    if b==0: raise ValueError('Деление на ноль.')
                    return a/b
                if not b.is_number or not b.is_real or abs(float(b))>12:
                    raise ValueError('Степень должна быть числом от -12 до 12.')
                return a**b
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in functions and not node.keywords and len(node.args)==1:
                return functions[node.func.id](visit(node.args[0],depth+1))
            raise ValueError('Недопустимая операция. Используй числа, скобки, x/y/z/t и стандартные функции.')
        result=visit(tree.body)
        if sp.count_ops(result)>160: raise ValueError('Слишком сложное выражение.')
        return result
    query=query.strip()
    if operation=='solve':
        if query.count('=')>1: raise ValueError('Допустимо одно равенство.')
        lhs,rhs=query.split('=',1) if '=' in query else (query,'0')
        expr=parse(lhs)-parse(rhs)
    else:
        if '=' in query: raise ValueError('Для уравнений выбери «Решить уравнение».')
        expr=parse(query)
    v=symbols[variable]
    if operation in ('solve','integrate','factor'):
        try: degree=sp.Poly(expr,v).degree()
        except (sp.PolynomialError,ValueError) as exc:
            raise ValueError('Эта операция поддерживает многочлены.') from exc
        if degree>8: raise ValueError('Поддерживается степень не выше восьмой.')
    if operation=='solve':
        result=sp.solveset(expr,v,domain=sp.S.Reals)
        if not isinstance(result,sp.FiniteSet): raise ValueError('Конечные действительные корни не найдены.')
    elif operation=='diff': result=sp.diff(expr,v)
    elif operation=='integrate': result=sp.integrate(expr,v)+sp.Symbol('C')
    elif operation=='factor': result=sp.factor(expr)
    else: result=sp.cancel(expr)
    if sp.count_ops(result)>300: raise ValueError('Слишком сложный результат.')
    result_text=str(result)
    if len(result_text)>2500: raise ValueError('Слишком длинный результат.')
    return {'ok':True,'operation':operation,'input':query,'result':result_text,
            'latex':sp.latex(result),'approx':str(sp.N(result,12)) if not getattr(result,'free_symbols',set()) and not isinstance(result,sp.Set) else None}
