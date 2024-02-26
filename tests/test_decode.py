import pytest
import binascii
from miasmX.arch.ia32_arch import x86mnemo

tests = [
('dbe9',       'fucomi    st, st(1)',            'fucomi    %st(1), %st'),
('dbd8',       'fcmovnu   st, st(0)',            'fcmovnu   %st(0), %st'),
('def9',       'fdivp     st(1), st',            'fdivrp    %st, %st(1)'),
('a4',         'movsb     ',                     'movsb     '),
('06',         'push      es',                   'pushl     %es'),
('d8c1',       'fadd      st, st(1)',            'fadd      %st(1), %st'),
('f2ae',       'repnz scasb     ',               'repnz scasb     '),
('ec',         'in        al, dx',               'in        %dx, %al'),
('66ec',       'in        al, dx',               'in        %dx, %al'),
('c6450002',   'mov       BYTE PTR [ebp], 2',    'movb      $2, (%ebp)'),
('c64500fe',   'mov       BYTE PTR [ebp], 254',  'movb      $254, (%ebp)'),
('662e0f1f840000000000',
               'nop       WORD PTR cs:[eax+eax]','nop       %cs:(%eax,%eax)'),
('660f72d101', 'psrld     xmm1, 1',              'psrld     $1, %xmm1'),
('f390',       'pause     ',                     'pause     '),
('ffe0',       'jmp       eax',                  'jmp       *%eax'),
('3effe0',     'notrack jmp       eax',          'notrack jmp       *%eax'),
('f30f1efb',   'endbr32   ',                     'endbr32   '),
('f30f1efa',   'endbr64   ',                     'endbr64   '),
]

@pytest.mark.parametrize("bin, intel, att", tests)
def test_decoder(bin, intel, att):
    op = x86mnemo.dis(binascii.unhexlify(bin))
    assert intel == str(op)
    assert att == op.__str__(asm_format='att_syntax binutils')
