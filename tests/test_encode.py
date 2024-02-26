import pytest
import binascii
from miasmX.arch.ia32_arch import x86mnemo

tests = [
('nop',             'nop',             '90'),
('pause',           'pause',           'f390'),
]

@pytest.mark.parametrize("intel, att, bin", tests)
def test_encode(intel, att, bin):
    b = x86mnemo.asm(intel)
    assert len(b) > 0                  # Cannot asm
    assert binascii.unhexlify(bin) == b[0]
