import pytest
import binascii
from miasmx.arch.ia32_arch import x86mnemo

tests = [
('nop',             'nop',               '90'),
('pause',           'pause',             'f390'),
('xchg eax, ebx',   'xchgl %ebx, %eax',  '93'),
('jmp eax',         'jmp *%eax',         'ffe0'),
('notrack jmp eax', 'notrack jmp *%eax', '3effe0'),
('endbr32',         'endbr32',           'f30f1efb'),
('endbr64',         'endbr64',           'f30f1efa'),
('jmp 2',           'jmp 2',             'e902000000'),
('jg 2',            'jg 2',              '7f02'),
('ret 4',           'ret $4',            'c20400'),
]

@pytest.mark.parametrize("intel, att, bin", tests)
def test_encode_intel(intel, att, bin):
    b = x86mnemo.asm(intel)
    assert len(b) > 0                  # Cannot asm
    assert binascii.unhexlify(bin) == b[0]

@pytest.mark.parametrize("intel, att, bin", tests)
def test_encode_att(intel, att, bin):
    b = x86mnemo.asm_att(att)
    assert len(b) > 0                  # Cannot asm
    assert binascii.unhexlify(bin) == b[0]
