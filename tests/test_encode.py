import pytest
import binascii
from miasmX.arch.ia32_arch import x86mnemo

tests = [
('nop',             'nop',               '90'),
('pause',           'pause',             'f390'),
('jmp eax',         'jmp *%eax',         'ffe0'),
('notrack jmp eax', 'notrack jmp *%eax', '3effe0'),
('endbr32',         'endbr32',           'f30f1efb'),
('endbr64',         'endbr64',           'f30f1efa'),
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
