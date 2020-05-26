#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
# Modifications (C) 2011-2017 Airbus, Louis.Granboulan@airbus.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
from miasmX.arch.ia32_reg import x86_afs
from miasmX.tools.modint import int32, uint32

reglist_for_size = {
    x86_afs.u08: x86_afs.reg_list8,
    x86_afs.u32: x86_afs.reg_list32,
    }
def arg2txt(a):
    if 'txt' in a:
        return a['txt']
    if x86_afs.size in a:
        reg_no = [ key for key in a if type(key) == int ]
        if len(reg_no) != 1:
            return a
        reg_no = reg_no[0]
        for c in [1,2,4,8]:
            for r in reglist_for_size:
                if a[x86_afs.size] == r*c:
                    if a[reg_no] != c:
                        raise ValueError("Count is %d instead of %d"%(a[reg_no],c))
                    if c==1:
                        return reglist_for_size[r][reg_no]
                    return "%s*%d"%(reglist_for_size[r][reg_no],c)
        TODO
        return a
    if x86_afs.imm in a:
        return a[x86_afs.imm]
    return a

def dict_add(a, b):
    tmp = dict(a)
    for k in b:
        #special case
        if k == x86_afs.symb:
            if k in tmp:
                tmp[k] = dict_add(tmp[k], b[k])
                del tmp[k]['txt']
            else:
                tmp[k] = dict(b[k])
            continue
        #normal case
        if k in tmp:
            tmp[k]+=b[k]
        else:
            tmp[k] = b[k]
        if tmp[k]==0:
            del(tmp[k])
    tmp['txt'] = "%s+%s" % (arg2txt(a), arg2txt(b))
    return tmp

def dict_sub(a, b):
    tmp = dict(a)
    for k in b:
        #special case
        if k == x86_afs.symb:
            if k in tmp:
                tmp[k] = dict_sub(tmp[k], b[k])
            else:
                tmp[k] = dict({},b[k])
            if tmp[k] == dict():
                del tmp[k]
            continue
        #normal case
        if k in tmp:
            tmp[k] -= b[k]
        else:
            tmp[k] = -b[k]
        if tmp[k] == 0:
            del tmp[k]
    return tmp

def dict_mul(a, b):
    if list(a.keys()) == [x86_afs.imm]:
        ret = {}
        for k in b:
            if k == x86_afs.symb:
                ret[k] = dict_mul({x86_afs.imm:a[x86_afs.imm]}, b[k])
            else:
                ret[k] = a[x86_afs.imm]*b[k]
        return ret
    if list(b.keys()) == [x86_afs.imm]:
        ret = {}
        for k in a:
            if k == x86_afs.symb:
                ret[k] = dict_mul({x86_afs.imm:b[x86_afs.imm]}, a[k])
            else:
                ret[k] = b[x86_afs.imm]*a[k]
        return ret
    raise ValueError('bad dict mul %s %s'%(a,b))

keywords = ("BYTE", "WORD", "DWORD", "QWORD", "SINGLE", "DOUBLE", "TBYTE", "XWORD", "XMMWORD",
            "PTR", "OFFSET", "FLAT")

tokens = keywords +(
    'NUMBER',
    'PLUS','MINUS','TIMES',
    'LPAREN','RPAREN','LBRA','RBRA','COLON','PERCENT','DOT',
    'SEGMENT','REGISTER','NAME',
    )

# Tokens

t_PLUS    = r'\+'
t_MINUS   = r'-'
t_TIMES   = r'\*'
t_LPAREN  = r'\('
t_RPAREN  = r'\)'
t_LBRA  = r'\['
t_RBRA  = r'\]'
t_COLON    = r':'
t_PERCENT  = r'%'
t_DOT  = r'\.'

registers = {}
for name in x86_afs.reg_list32:
    registers[name] = x86_afs.u32
for name in x86_afs.reg_list16:
    registers[name] = x86_afs.u16
for name in x86_afs.reg_list8:
    registers[name] = x86_afs.u08
for name in x86_afs.reg_flt:
    registers[name] = x86_afs.f32
registers['st'] = registers['st0']
#for name in x86_afs.reg_dr:
#    registers[name] = x86_afs.u32
#for name in x86_afs.reg_cr:
#    registers[name] = x86_afs.u32
for name in x86_afs.reg_mm:
    registers[name] = x86_afs.mm
for name in x86_afs.reg_xmm:
    registers[name] = x86_afs.xmm

segments = {}
for name in x86_afs.reg_sg:
    segments[name] = x86_afs.u32

def t_NAME(t):
    r'([a-zA-Z_][a-zA-Z0-9_.$]*|\.L[a-zA-Z0-9_]+)(@[a-zA-Z]+)?|[0-9]+[bf]|\[\.-\.L[A-Z]*[0-9]*\]'
    if t.value.upper() in keywords:
        t.type = t.value.upper()
    if t.value.lower() in segments:
        t.type = 'SEGMENT'
    if t.value.lower() in registers:
        t.type = 'REGISTER'
    return t

def t_NUMBER(t):
    r'((((0x)|(0X))[0-9a-fA-F]+)|(\d+))'
    try:
        if t.value.startswith("0x") or t.value.startswith("0X"):
            t.value = int(t.value, 16)
        else:
            t.value = int(t.value)
    except ValueError:
        print("Integer value too large %d", t.value)
        t.value = 0
    return t

# Ignored characters
t_ignore = " \t"

def t_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")

def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)


# Build the lexer
try:
    import ply.lex as lex
except ImportError:
    import sys, os
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    import ply.lex as lex
lexer_intel = lex.lex()

def p_error(t):
    if t is None:
        raise ValueError('Error in YACC: unexpected EOF')
    else:
        import inspect
        frame = inspect.currentframe()
        arg = frame.f_back.f_back.f_locals['input']
        line = frame.f_back.f_back.f_back.f_back.f_locals['l']
        raise ValueError('Error in YACC parsing token %s\n\tin arg %r\n\tfor line %r'%(t,arg,line))

precedence = (
    ('left','PLUS','MINUS'),
    ('left','TIMES'),
    ('right','UMINUS'),
    )

def p_address_1(t):
    '''address : formula'''
    t[0] = t[1]

def p_address_2(t):
    '''address : ptrformula'''
    t[0] = t[1]

def p_address_3(t):
    '''address : SEGMENT'''
    # e.g. "push es"
    t[0] ={x86_afs.reg_dict[t[1]]:1, x86_afs.size : x86_afs.u32}

def p_address_4(t):
    '''address : opt_seg_colon expression'''
    t[2].update(t[1])
    t[0] = t[2]

def p_ptrformula_1(t):
    '''ptrformula : PTRSIZE formula
                  | PTRSIZE symbolregister'''
    t[2].update(t[1])
    t[0] = t[2]

def p_ptrformula_2(t):
    '''ptrformula : PTRSIZE opt_seg_colon formula'''
    t[0] = t[1]
    if t[2][x86_afs.segm] != 3:
        # We don't mention the DS segment, which is implicit
        t[0].update(t[2])
    t[0].update(t[3])

def p_symbolregister(t):
    '''symbolregister : REGISTER
                      | SEGMENT'''
    t[0] = {x86_afs.symb:{t[1]:1}}

def p_formula(t):
    '''formula : expression
               | brackets'''
    t[0] = t[1]

def p_PTRSIZE(t):
    '''PTRSIZE : BYTE PTR
               | WORD PTR
               | DWORD PTR
               | QWORD PTR
               | SINGLE PTR
               | DOUBLE PTR
               | TBYTE PTR
               | XWORD PTR
               | XMMWORD PTR
                 '''
    size = {
        'byte': x86_afs.u08,
        'word': x86_afs.u16,
        'dword': x86_afs.u32,
        'qword': x86_afs.f64,
        'single': x86_afs.f32,
        'double': x86_afs.f64,
        'tbyte': x86_afs.f80,
        'xword': x86_afs.f80,
        'xmmword': x86_afs.xmm,
        }[t[1].lower()]
    t[0] = {x86_afs.ad: size}

def p_opt_seg_colon_1(t):
    '''opt_seg_colon : SEGMENT COLON '''
    t[0] = {x86_afs.segm:x86_afs.reg_sg.index(t[1])}

def p_expression_1(t):
    '''expression : MINUS expression %prec UMINUS'''
    t[0] = dict([[k,-t[2][k]] for k in t[2]])

def p_expression_1a(t):
    '''expression : LPAREN DOT MINUS NAME RPAREN'''
    name = "[.-%s]" % t[4]  # Same syntax as for AT&T parser
    t[0] = {x86_afs.symb:{name:1}}

def p_expression_2(t):
    '''expression : expression PLUS expression
                  | expression MINUS expression
                  | expression TIMES expression'''
    if t[2] == '+':
        t[0] = dict_add(t[1], t[3])
    elif t[2] == '-':
        t[0] = dict_sub(t[1], t[3])
    elif t[2] == '*':
        t[0] = dict_mul(t[1], t[3])
    else:
        raise ValueError('bad op')

def p_expression_3(t):
    '''expression : LPAREN expression RPAREN'''
    t[0] = t[2]

def p_expression_4(t):
    '''expression : OFFSET FLAT COLON expression '''
    t[0] = t[4]

def p_expression_5(t):
    '''expression : NUMBER'''
    t[0] = {x86_afs.imm:int(int32(uint32(int(t[1]))))}

def p_expression_6(t):
    '''expression : symbol
                  | register'''
    t[0] = t[1]

def p_register_0(t):
    '''register : REGISTER'''
    reg = t[1].lower()
    if reg == 'st': reg = 'st0'
    t[0] = {x86_afs.reg_dict[reg]:1, x86_afs.size: registers[reg]}

def p_register_1(t):
    '''register : PERCENT REGISTER'''
    reg = t[2].lower()
    if reg == 'st': reg = 'st0'
    t[0] = {x86_afs.reg_dict[reg]:1, x86_afs.size: registers[reg]}

def p_register_2st(t):
    '''register : REGISTER LPAREN NUMBER RPAREN'''
    t[0] = t[1] + "%d"%t[3]
    t[0] ={x86_afs.reg_dict[t[0]]:1, x86_afs.size : x86_afs.f32}

def p_register_3st(t):
    '''register : PERCENT REGISTER LPAREN NUMBER RPAREN'''
    t[0] = t[2] + "%d"%t[4]
    t[0] ={x86_afs.reg_dict[t[0]]:1, x86_afs.size : x86_afs.f32}

def p_symbol_0(t):
    '''symbol : NAME'''
    t[0] = {x86_afs.symb:{t[1]:1}}
for k in keywords:
    p_symbol_0.__doc__ += "\n| %s"%k

def p_brackets_1(t):
    '''brackets : LBRA expression RBRA
                | LBRA ptrformula RBRA '''
    if not x86_afs.ad in t[2]:
        t[2][x86_afs.ad] = True
    t[0] = t[2]

def p_brackets_2(t):
    '''brackets : symbol LBRA expression RBRA '''
    if not x86_afs.ad in t[3]:
        t[3][x86_afs.ad] = True
    t[0] = t[3]
    for f in t[1]:
        t[0][f] = t[1][f]

def p_brackets_3(t):
    '''brackets : NUMBER LBRA expression RBRA '''
    if not x86_afs.ad in t[3]:
        t[3][x86_afs.ad] = True
    t[0] = t[3]
    t[0][x86_afs.imm] = int(int32(uint32(int(t[1]))))

def p_brackets_4(t):
    '''brackets : MINUS NUMBER LBRA expression RBRA'''
    if not x86_afs.ad in t[4]:
        t[4][x86_afs.ad] = True
    t[0] = t[4]
    t[0][x86_afs.imm] = - int(int32(uint32(int(t[2]))))

def p_brackets_5(t):
    '''brackets : NUMBER PLUS symbol LBRA expression RBRA '''
    if not x86_afs.ad in t[5]:
        t[5][x86_afs.ad] = True
    t[0] = t[5]
    for f in t[3]:
        t[0][f] = t[3][f]
    t[0][x86_afs.imm] = int(int32(uint32(int(t[1]))))

def p_brackets_6(t):
    '''brackets : MINUS NUMBER PLUS symbol LBRA expression RBRA %prec UMINUS'''
    if not x86_afs.ad in t[6]:
        t[6][x86_afs.ad] = True
    t[0] = t[6]
    for f in t[4]:
        t[0][f] = t[4][f]
    t[0][x86_afs.imm] = - int(int32(uint32(int(t[2]))))

import ply.yacc as yacc
import tempfile
parser_intel = yacc.yacc(debug=0,
    outputdir=tempfile.gettempdir(), tabmodule="ply_ia32_intel_20150429")

def parse_ad(a):
    l = parser_intel.parse(a, lexer = lexer_intel)
    if not x86_afs.ad in l:
        l[x86_afs.ad] = False
    else:
        l[x86_afs.size] = l[x86_afs.ad]
    if not x86_afs.size in l:
        l[x86_afs.size] = x86_afs.u32
    return l
