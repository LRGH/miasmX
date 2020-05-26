# (C) 2011-2017 Airbus, Louis.Granboulan@airbus.com

from miasmX.arch.ia32_reg import x86_afs

tokens = (
    'NUMBER',
    'PLUS','MINUS','TIMES',
    'LPAREN','RPAREN','COLON','PERCENT','DOLLAR','COMMA',
    'ST','SEGMENT','REGISTER','NAME',
    )

# Tokens

t_PLUS    = r'\+'
t_MINUS   = r'-'
t_TIMES   = r'\*'
t_LPAREN  = r'\('
t_RPAREN  = r'\)'
t_COLON   = r':'
t_PERCENT = r'%'
t_DOLLAR  = r'\$'
t_COMMA   = r','

registers = {}
for name in x86_afs.reg_list32:
    registers[name] = x86_afs.u32
for name in x86_afs.reg_list16:
    registers[name] = x86_afs.u16
for name in x86_afs.reg_list8:
    registers[name] = x86_afs.u08
#for name in x86_afs.reg_flt:
#    registers[name] = x86_afs.f32
for name in x86_afs.reg_dr:
    registers[name] = x86_afs.u32
for name in x86_afs.reg_cr:
    registers[name] = x86_afs.u32
for name in x86_afs.reg_mm:
    registers[name] = x86_afs.mm
for name in x86_afs.reg_xmm:
    registers[name] = x86_afs.xmm

segments = {}
for name in x86_afs.reg_sg:
    segments[name] = x86_afs.u32
    registers[name] = x86_afs.size_seg

def t_NAME(t):
    r'([a-zA-Z_][a-zA-Z0-9_.$]*|\.L[a-zA-Z0-9_.]+)(@[a-zA-Z]+)?|[0-9]+[bf]|\[\.-\.L[A-Z]*[0-9]*\]'
    if t.value.lower() in registers:
        t.type = 'REGISTER'
    if t.value.lower() in segments:
        t.type = 'SEGMENT'
    if t.value.lower() == 'st':
        t.type = 'ST'
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
lexer_att = lex.lex()

def p_error(t):
    raise ValueError('Error in YACC %s'%t)

precedence = (
    ('left','PLUS','MINUS'),
    ('left','TIMES'),
    ('right','UMINUS'),
    )

def p_arglist_0(t):
    '''arglist : argument'''
    t[0] = [t[1]]

def p_arglist_1(t):
    '''arglist : argument COMMA argument'''
    t[0] = [t[3], t[1]]

def p_arglist_2(t):
    '''arglist : argument COMMA argument COMMA argument'''
    t[0] = [t[5], t[3], t[1]]

def p_argument_1a(t):
    '''argument : register'''
    t[0] = t[1]

def p_argument_1b(t):
    '''argument : TIMES register'''
    t[0] = t[2]

def p_argument_1c(t):
    '''argument : TIMES address'''
    t[0] = t[2]
    t[0][x86_afs.ad] = x86_afs.u32

def p_argument_2(t):
    '''argument : DOLLAR constant'''
    t[0] = t[2]

def p_argument_3(t):
    '''argument : address'''
    t[0] = t[1]
    t[0][x86_afs.ad] = True

def p_argument_4(t):
    '''argument : PERCENT SEGMENT COLON address'''
    t[0] = {
        x86_afs.segm:x86_afs.reg_sg.index(t[2]),
        x86_afs.ad:x86_afs.u32,
        }
    t[0].update(t[4])

def p_symbol_0(t):
    '''symbol : NAME
              | ST
              | SEGMENT
              | REGISTER'''
    t[0] = {x86_afs.symb:{t[1]:1}}

def p_register_1(t):
    '''register : PERCENT SEGMENT
                | PERCENT REGISTER'''
    reg = t[2].lower()
    t[0] = {x86_afs.reg_dict[reg]:1, x86_afs.size: registers[reg], 'txt':reg}

def p_register_2(t):
    '''register : PERCENT ST LPAREN NUMBER RPAREN'''
    t[0] = t[2] + "%d"%t[4]
    t[0] ={x86_afs.reg_dict[t[0]]:1, x86_afs.size:x86_afs.f32}

def p_register_2b(t):
    '''register : PERCENT ST'''
    t[0] = t[2] + "0"
    t[0] ={x86_afs.reg_dict[t[0]]:1, x86_afs.size : x86_afs.f32}

def p_address_1(t):
    '''address : constant'''
    t[0] = t[1]

def p_address_2(t):
    '''address : deref'''
    t[0] = t[1]

def p_address_3(t):
    '''address : constant deref'''
    t[0] = t[2]
    t[0].update(t[1])

def p_deref_1(t):
    '''deref : LPAREN register RPAREN'''
    t[0] = t[2]

def p_deref_2(t):
    '''deref : LPAREN register COMMA register RPAREN'''
    del t[4][x86_afs.size]
    reg = x86_afs.reg_dict[t[4]['txt']]
    t[0] = t[2]
    t[0][reg] = 1 + t[0].get(reg, 0)
    t[0]['txt'] = "%s+%s"%(t[2]['txt'],t[4]['txt'])

def p_deref_3(t):
    '''deref : LPAREN register COMMA register COMMA number RPAREN'''
    del t[4][x86_afs.size]
    reg = x86_afs.reg_dict[t[4]['txt']]
    t[0] = t[2]
    t[0][reg] = t[6] + t[0].get(reg, 0)
    t[0]['txt'] = "%s+%s*%s"%(t[2]['txt'],t[4]['txt'],t[6])

def p_deref_4(t):
    '''deref : LPAREN COMMA register COMMA number RPAREN'''
    reg = x86_afs.reg_dict[t[3]['txt']]
    t[0] = t[3]
    t[0][reg] = t[5]
    t[0]['txt'] = "%s*%s"%(t[3]['txt'],t[5])

def p_constant_1(t):
    '''constant : number'''
    t[0] = {x86_afs.imm:t[1]}

def p_constant_2(t):
    '''constant : symbol'''
    t[0] = t[1]

def p_constant_3(t):
    '''constant : constant PLUS constant'''
    t[0] = t[1]
    if x86_afs.symb in t[1] and x86_afs.symb in t[3]:
        t[3][x86_afs.symb].update(t[1][x86_afs.symb])
    t[0].update(t[3])

def p_constant_4(t):
    '''constant : constant MINUS number'''
    t[0] = t[1]
    t[0][x86_afs.imm] = t[0].get(x86_afs.imm, 0) - t[3]

def p_constant_5(t):
    '''constant : constant MINUS symbol'''
    s = get_symbol(t[3])
    t[0] = t[1]
    t[0][x86_afs.symb][s] = t[0][x86_afs.symb].get(s, 0) - 1
    if t[0][x86_afs.symb][s] == 0:
        del t[0][x86_afs.symb][s]
    if t[0][x86_afs.symb] == dict():
        del t[0][x86_afs.symb]

def p_constant_6(t):
    '''constant : LPAREN symbol MINUS symbol RPAREN PLUS number'''
    s = get_symbol(t[4])
    t[0] = t[2]
    t[0][x86_afs.symb][s] = -1
    t[0][x86_afs.imm] = t[7]

def p_constant_7(t):
    '''constant : LPAREN symbol MINUS symbol RPAREN MINUS number'''
    s = get_symbol(t[4])
    t[0] = t[2]
    t[0][x86_afs.symb][s] = -1
    t[0][x86_afs.imm] = -t[7]

def p_number_0(t):
    '''number : NUMBER'''
    t[0] = t[1]

def p_number_1(t):
    '''number : MINUS number %prec UMINUS'''
    t[0] = -t[2]

import ply.yacc as yacc
import tempfile
parser_att = yacc.yacc(debug=0,
    outputdir=tempfile.gettempdir(), tabmodule="ply_ia32_att_20150429")

def get_symbol(t):
    return list(t[x86_afs.symb].keys())[0]

def parse_args(a):
    if a == '':
        return []
    args = parser_att.parse(a, lexer = lexer_att)
    for l in args:
        if l == {}:
            l[x86_afs.imm] = 0
        if not x86_afs.ad in l:
            l[x86_afs.ad] = False
        else:
            l[x86_afs.size] = l[x86_afs.ad]
        if not x86_afs.size in l:
            l[x86_afs.size] = x86_afs.u32
    return args

import re
from miasmX.arch.ia32_arch import prefix_dic
def parse_asm_x86(line):
    words = re.split(r"\s+", line)
    prefix = []
    while len(words):
        name = words.pop(0)
        if name in prefix_dic:
            prefix.append(prefix_dic[name])
            name = ''
        elif name != '':
            break
    return prefix, name, ' '.join(words)
