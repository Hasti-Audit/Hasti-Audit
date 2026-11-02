# Hasti Client Scanner v12r
# Run: python hasti_client_scanner.py > report.md
# Send only report.md back.

import os,ast,base64
from datetime import datetime,timezone

def _d(s):
    return base64.b64decode(s).decode()

class T(ast.NodeVisitor):
    def __init__(self):
        self.m,self.n={},{}
    def visit_Import(self,node):
        for a in node.names:
            loc=a.asname or a.name
            root=a.name.split('.')[0]
            self.m[loc]=root; self.m[a.name]=root
    def visit_ImportFrom(self,node):
        if not node.module: return
        root=node.module.split('.')[0]
        for a in node.names:
            if a.name=='*': continue
            self.n[a.asname or a.name]=(root,a.name)

def _t(n): return isinstance(n,ast.Constant) and n.value is True
def _s(n):
    return n.value if isinstance(n,ast.Constant) and isinstance(n.value,str) else None

def scan(code,fn='f.py'):
    out=[]
    try: tree=ast.parse(code)
    except Exception: return out
    tr=T(); tr.visit(tree)

    def ma(f,mod,attrs):
        if isinstance(f,ast.Attribute) and isinstance(f.value,ast.Name):
            return tr.m.get(f.value.id,f.value.id)==mod and f.attr in attrs
        return False
    def dn(f,mod,names):
        if isinstance(f,ast.Name) and f.id in tr.n:
            r,o=tr.n[f.id]; return r==mod and o in names
        return False
    def imp(c,mod):
        return isinstance(c,ast.Call) and isinstance(c.func,ast.Name) and c.func.id==_d('X19pbXBvcnRfXw==') and c.args and _s(c.args[0])==mod
    def ind(f):
        if isinstance(f,ast.Attribute) and f.attr in (_d('ZXZhbA=='),_d('ZXhlYw==')):
            if isinstance(f.value,ast.Name) and f.value.id in (_d('X19idWlsdGluc19f'),_d('YnVpbHRpbnM=')): return f.attr
        if isinstance(f,ast.Call) and isinstance(f.func,ast.Name) and f.func.id==_d('Z2V0YXR0cg==') and len(f.args)>=2:
            n=_s(f.args[1])
            if n in (_d('ZXZhbA=='),_d('ZXhlYw==')) and isinstance(f.args[0],ast.Name) and f.args[0].id in (_d('X19idWlsdGluc19f'),_d('YnVpbHRpbnM=')): return n
        return None
    def obf(f):
        if not (isinstance(f,ast.Call) and isinstance(f.func,ast.Name) and f.func.id==_d('Z2V0YXR0cg==') and len(f.args)>=2): return False
        n=_s(f.args[1])
        if n not in (_d('bG9hZA=='),_d('bG9hZHM=')): return False
        o=f.args[0]
        if imp(o,_d('cGlja2xl')): return True
        if isinstance(o,ast.Name) and tr.m.get(o.id,o.id)==_d('cGlja2xl'): return True
        return False
    def ex(f):
        return (isinstance(f,ast.Attribute) and f.attr in (_d('ZXhlY3V0ZQ=='),_d('ZXhlY3V0ZW1hbnk='))) or (isinstance(f,ast.Name) and f.id in (_d('ZXhlY3V0ZQ=='),_d('ZXhlY3V0ZW1hbnk=')))
    def dyn(a):
        if isinstance(a,ast.JoinedStr): return True
        if isinstance(a,ast.BinOp) and isinstance(a.op,(ast.Add,ast.Mod)): return True
        if isinstance(a,ast.Call) and isinstance(a.func,ast.Attribute) and a.func.attr==_d('Zm9ybWF0'): return True
        return False

    for node in ast.walk(tree):
        if not isinstance(node,ast.Call): continue
        f,line=node.func,getattr(node,'lineno',None)
        if ma(f,_d('cGlja2xl'),{_d('bG9hZA=='),_d('bG9hZHM=')}) or dn(f,_d('cGlja2xl'),{_d('bG9hZA=='),_d('bG9hZHM=')}):
            out.append(f"- HIGH | {fn}:{line} | R1")
        if obf(f): out.append(f"- HIGH | {fn}:{line} | R1x")
        if ma(f,_d('dG9yY2g='),{_d('bG9hZA==')}) or dn(f,_d('dG9yY2g='),{_d('bG9hZA==')}):
            ok=any(k.arg==_d('d2VpZ2h0c19vbmx5') and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords)
            if not ok: out.append(f"- HIGH | {fn}:{line} | R2")
        if ma(f,_d('b3M='),{_d('c3lzdGVt'),_d('cG9wZW4=')}) or dn(f,_d('b3M='),{_d('c3lzdGVt'),_d('cG9wZW4=')}):
            out.append(f"- HIGH | {fn}:{line} | R3")
        if ma(f,_d('c3VicHJvY2Vzcw=='),{_d('cnVu'),_d('Y2FsbA=='),'Popen',_d('Y2hlY2tfb3V0cHV0'),_d('Y2hlY2tfY2FsbA==')}) or dn(f,_d('c3VicHJvY2Vzcw=='),{_d('cnVu'),_d('Y2FsbA=='),'Popen',_d('Y2hlY2tfb3V0cHV0'),_d('Y2hlY2tfY2FsbA==')}):
            for k in node.keywords:
                if k.arg==_d('c2hlbGw=') and _t(k.value): out.append(f"- HIGH | {fn}:{line} | R4")
        if ma(f,_d('eWFtbA=='),{_d('bG9hZA==')}) or dn(f,_d('eWFtbA=='),{_d('bG9hZA==')}):
            if not any(k.arg==_d('TG9hZGVy') for k in node.keywords): out.append(f"- HIGH | {fn}:{line} | R5")
        if isinstance(f,ast.Name) and f.id in (_d('ZXZhbA=='),_d('ZXhlYw==')): out.append(f"- HIGH | {fn}:{line} | R6")
        d=ind(f)
        if d: out.append(f"- HIGH | {fn}:{line} | R6x")
        if ex(f) and node.args and dyn(node.args[0]): out.append(f"- HIGH | {fn}:{line} | R7")
        if isinstance(f,ast.Attribute) and f.attr in (_d('Zml0'),_d('Zml0X3RyYW5zZm9ybQ==')):
            if node.args and isinstance(node.args[0],ast.Name) and node.args[0].id in ('X','df','data'):
                out.append(f"- MEDIUM | {fn}:{line} | R8")
    return out

if __name__=='__main__':
    print('# Hasti Audit Report\n')
    print(f'**Scan date:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}')
    print('**Scanner:** Hasti Client Scanner v12r')
    print('**Scope:** static pre-check\n\n## Findings\n')
    rows=[]
    for root,dirs,files in os.walk('.'):
        dirs[:]=[d for d in dirs if not d.startswith('.') and d not in ('__pycache__','venv','.venv','node_modules','env')]
        for f in files:
            if f.endswith('.py'):
                p=os.path.join(root,f)
                try:
                    rows += scan(open(p,encoding='utf-8',errors='ignore').read(),p)
                except Exception:
                    pass
    print('No issues found.' if not rows else '\n'.join(rows))
    print('\n---\n*Technical indicators only. Human review required.*')
