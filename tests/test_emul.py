import pytest
import binascii
from miasmx.arch.ia32_arch import x86mnemo
from miasmx.tools import emul_helper
from miasmx.tools.modint import uint32
from miasmx.expression.expression import ExprInt

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
def test_emul_instr(bin, result, expressions):
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

# AT&T syntax expected below
piece_of_code = [
('''xchgl %ebx, %eax
addl $2, %ecx
subl $2, %ecx
adcl $2, %ecx
negl %ecx
xorl %edx, %edx
xaddl %edx, %ecx
notl %edx
rorl %cl, %eax
roll $6, %eax
sbbl $-1, %ebx
orl %edx, %eax
andl %edx, %eax''',
  [],
  ['ac init_ac', 'af ((init_eax+(- (((init_ebx >>> (((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)[0:8]+0xFFFFFFFA))&0x1),0,1, 0x0,1,32))+0x1)&0x10)?(0x1,0x0)', 'cf 0x0', 'cr0 init_cr0', 'cs 0x9', 'df init_df', 'dr7 0x0', 'eax ((((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)^0xFFFFFFFF)&((init_ebx >>> (((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)[0:8]+0xFFFFFFFA))|(((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)^0xFFFFFFFF)))', 'ebp init_ebp', 'ebx (init_eax+(- (((init_ebx >>> (((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)[0:8]+0xFFFFFFFA))&0x1),0,1, 0x0,1,32))+0x1)', 'ecx ((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)', 'edi init_edi', 'edx (((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)^0xFFFFFFFF)', 'esi init_esi', 'esp init_esp', 'i_d init_i_d', 'i_f init_i_f', 'iopl_f init_iopl', 'nf ((((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)^0xFFFFFFFF)&((init_ebx >>> (((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)[0:8]+0xFFFFFFFA))|(((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)^0xFFFFFFFF)))[31:32]', 'nt init_nt', 'of 0x0', 'pf (parity ((((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)^0xFFFFFFFF)&((init_ebx >>> (((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)[0:8]+0xFFFFFFFA))|(((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)^0xFFFFFFFF))))', 'rf init_rf', 'tf init_tf', 'tsc1 init_tsc1', 'tsc2 init_tsc2', 'vif init_vif', 'vip init_vip', 'vm init_vm', 'zf ((((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)^0xFFFFFFFF)&((init_ebx >>> (((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)[0:8]+0xFFFFFFFA))|(((- init_ecx)+(- ((((init_ecx^(init_ecx+0x2))&((init_ecx+0x2)^0x2))[31:32]^(init_ecx^(init_ecx+0x2)^0x2)[31:32]),0,1, 0x0,1,32))+0xFFFFFFFE)^0xFFFFFFFF)))?(0x0,0x1)']),

('''fdiv %st, %st(2)
fdivr %st, %st(2)
fsub %st, %st(2)
fsubr %st, %st(2)
movl %eax, 32(%esi)
fdivl 32(%esi)
fdivrl 32(%esi)
fsubl 32(%esi)
fsubrl 32(%esi)
fmul %st, %st(2)
fmull 32(%esi)
pslldq $4, %xmm3''',
  ['@32[(init_esi+0x20)] init_eax'],
  ['ac init_ac', 'af init_af', 'cf init_cf', 'cr0 init_cr0', 'cs 0x9', 'df init_df', 'dr7 0x0', 'eax init_eax', 'ebp init_ebp', 'ebx init_ebx', 'ecx init_ecx', 'edi init_edi', 'edx init_edx', 'esi init_esi', 'esp init_esp', 'float_st0 (float_st0 fmul (mem_64_to_double (init_eax,0,32, @8[(init_esi+0x24)],32,40, @8[(init_esi+0x25)],40,48, @8[(init_esi+0x26)],48,56, @8[(init_esi+0x27)],56,64)))', 'float_st2 (float_st2 fmul float_st0)', 'i_d init_i_d', 'i_f init_i_f', 'iopl_f init_iopl', 'nf init_nf', 'nt init_nt', 'of init_of', 'pf init_pf', 'reg_float_cs 0x9', 'reg_float_eip 0x0', 'rf init_rf', 'tf init_tf', 'tsc1 init_tsc1', 'tsc2 init_tsc2', 'vif init_vif', 'vip init_vip', 'vm init_vm', 'xmm3 MMX(xmm3, 0x4, 0x0)', 'zf init_zf']),
]

def asm_att(instr):
    i = x86mnemo.asm_att(instr)
    if len(i) == 0:
        raise ValueError("Cannot asm %s"%instr)
    return x86mnemo.dis(i[0])

from miasmx.arch import ia32_sem
@pytest.mark.parametrize("lines, mem, reg", piece_of_code)
def test_emul_code(lines, mem, reg):
    lines = [ asm_att(_) for _ in lines.split('\n') ]
    machine = emul_helper.x86_machine()
    retval = emul_helper.emul_lines(machine, lines)
    assert mem == machine.dump_mem()
    print(machine.dump_id())
    assert reg == machine.dump_id()
    #assert set(reg) <= set(machine.dump_id())
