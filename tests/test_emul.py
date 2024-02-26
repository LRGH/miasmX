import pytest
import binascii
from miasmX.arch.ia32_arch import x86mnemo
from miasmX.tools import emul_helper
from miasmX.tools.modint import uint32
from miasmX.expression.expression import ExprInt

# expression display can depend on python version or on some non
# deterministic behaviour, a list of possibilities is defined below
tests = [
('dbe9',       '0x2',      [('zf = (float_st0 fcom float_st1)?(0x0,0x1)'),
                            ('pf = (float_st0 fcom float_st1)?(0x0,0x1)'),
                            ('cf = (float_st0 fcom float_st1)?(0x0,0x1)')]),
('dbd8',       '0x2',      [('float_st0 = zf?(float_st1,float_st0)')]),
('def9',       '0x2',      [('float_st0 = (float_st0 fdiv float_st1)'),
                            ('reg_float_eip = 0x0'),
                            ('reg_float_cs = cs'),
                            ('float_st1 = float_st2'),
                            ('float_st2 = float_st3'),
                            ('float_st3 = float_st4'),
                            ('float_st4 = float_st5'),
                            ('float_st5 = float_st6'),
                            ('float_st6 = float_st7'),
                            ('float_st7 = 0x0'),
                            ('float_stack_ptr = (float_stack_ptr - 0x1)')]),
('a4',         '0x1',      [('ds:@8[edi] = ds:@8[esi]'),
                            ('edi = df?((edi - 0x1),(edi+0x1))'),
                            ('esi = df?((esi - 0x1),(esi+0x1))')]),
('06',         '0x1',      [('esp = (esp - 0x4)'),
                            ('@16[(esp - 0x4)] = es')]),
('d8c1',       '0x2',      [('float_st0 = (float_st0 fadd float_st1)'),
                            ('reg_float_eip = 0x0'),
                            ('reg_float_cs = cs')]),
('ec',         '0x1',      [('vmcpu.vm_exception_flags = 0x800')]),
('66ec',       '0x2',      [('vmcpu.vm_exception_flags = 0x800')]),
('c6450002',   '0x4',      [('ds:@8[(ebp+0x0)] = 0x2',
                             'ds:@8[(0x0+ebp)] = 0x2')]),
('c64500fe',   '0x4',      [('ds:@8[(ebp+0x0)] = 0xFE',
                             'ds:@8[(0x0+ebp)] = 0xFE')]),
('662e0f1f840000000000',  '0xA',      []),
('660f72d101', '0x5',      [('xmm1 = MMX(xmm1, 0x1, 0x0)')]),
('ffe0',       'init_eax', [('eip = eax')]),
('3effe0',     'init_eax', [('eip = eax')]),
('f30f1efb',   '0x4',      []),
('f30f1efa',   '0x4',      []),
]

@pytest.mark.parametrize("bin, result, expressions", tests)
def test_decoder_intel(bin, result, expressions):
    op = x86mnemo.dis(binascii.unhexlify(bin))
    print(str(op))
    machine = emul_helper.x86_machine()
    retval = emul_helper.emul_lines(machine, [op])
    assert result == str(retval)
    my_eip = ExprInt(uint32(0x1000000))
    exprs = emul_helper.get_instr_expr(op, my_eip, [])
    assert len(expressions) == len(exprs)
    for i in range(len(expressions)):
        assert str(exprs[i]) in expressions[i]
