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
from miasmX.tools.modint import uint8, uint16, uint32, uint64, int8, int16, int32, int64
try:
    # Needed for compatibility with python2.3
    from plasmasm.python.compatibility import set, sorted
except ImportError:
    pass
import struct
import logging
from miasmX.arch.ia32_reg import x86_afs
import shlex


log = logging.getLogger("x86escape")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)
log.debug = lambda *x:None # Gains 5-10% time in parsing an asm file


tab_int_size = {int8:8,
                uint8:8,
                int16:16,
                uint16:16,
                int32:32,
                uint32:32,
                int64:64,
                uint64:64
                }

tab_size2int = {x86_afs.s08:int8,
                x86_afs.u08:uint8,
                x86_afs.s16:int16,
                x86_afs.u16:uint16,
                x86_afs.s32:int32,
                x86_afs.u32:uint32,
                }

tab_max_uint = {x86_afs.u08:0xFF, x86_afs.u16:0xFFFF, x86_afs.u32:uint32.limit-1, x86_afs.u64:uint64.limit-1}



prefix_dic = {"lock":0xF0, "repnz":0xF2, "repne":0xF2, "repz":0xF3, "repe":0xF3, "rep":0xF3, }

#'es'|'cs'|'ss'|'ds'|'fs'|'gs') ':' '''
prefix_seg = {0:0x26, 1:0x2E, 2:0x36, 3:0x3E, 4:0x64, 5:0x65}

prefix_seg_inv = dict(map(lambda x:(x[1],x[0]), prefix_seg.items()))

class mnemonic:
    def __init__(self, name, opc, afs, rm, modifs, modifs_orig, sem):
        self.name = name
        self.opc = opc

        self.afs = afs
        self.rm = rm

        self.modifs = modifs
        self.modifs_orig = modifs_orig

    def __str__(self):
        return self.name+' '+str(self.opc)+' '+str(self.afs)+' '+str(self.rm)+' '+str(self.modifs)+' '+str(self.modifs_orig)#+' '+str(self.sem)+' '


def mask_opc_to_i(mask, opc):
    log.debug("mask %x opc %x", mask, opc)
    return [i for i in range(0x100) if (i & mask) == opc]

mask_d = 0x38
mask_reg = 0xF8
mask_cond = 0xF0

d0 = 0<<3
d1 = 1<<3
d2 = 2<<3
d3 = 3<<3
d4 = 4<<3
d5 = 5<<3
d6 = 6<<3
d7 = 7<<3
reg = "reg"
noafs = "noafs"
cond = "cond"
cond_list = [["o"],
             ["no"],
             ["nae","c","b"],
             ["nb","nc","ae"],
             ["z","e"],
             ["nz","ne"],
             ["be"],
             ["a"],
             ["s"],
             ["ns"],
             ["pe","p"],
             ["po","np"],
             ["nge","l"],
             ["nl","ge"],
             ["ng","le"],
             ["nle","g"],
             ]
no_rm = []
rmr = "rmr"

imm = x86_afs.imm
ims = x86_afs.ims
mim = x86_afs.mim
u08 = x86_afs.u08
s08 = x86_afs.s08
u16 = x86_afs.u16
s16 = x86_afs.s16
u32 = x86_afs.u32
s32 = x86_afs.s32
im1 = x86_afs.im1
im3 = x86_afs.im3

r_eax = {x86_afs.r_eax:1, x86_afs.ad:False}
r_cl  = {x86_afs.reg_list8.index(x86_afs.r_cl):1, x86_afs.ad:False, x86_afs.size:x86_afs.u08}
r_ax  = {x86_afs.reg_list16.index(x86_afs.r_ax):1, x86_afs.ad:False, x86_afs.size:x86_afs.u16}
r_dx  = {x86_afs.reg_list16.index(x86_afs.r_dx):1, x86_afs.ad:False, x86_afs.size:x86_afs.u16}

r_es = 'es'
r_ss = 'ss'
r_cs = 'cs'
r_ds = 'ds'
r_fs = 'fs'
r_gs = 'gs'

segm_regs = [r_es, r_ss, r_cs, r_ds, r_fs, r_gs]

w8 = "w8"
se = "se"
sw = "sw"
ww = "ww"
sg = "sg" # segment reg
dr = "dr" # debug reg
cr = "cr" # control reg
ft = "ft" # float
w64= "w64"
sd = "sd" # single/double
wd = "wd" # word/dword
mmx = "mmx" # mmx instruction set
mm = "mm" # mm registers
xmm = "xmm" # xmm registers


bkf = "breakflow"
spf = "splitflow"
dtf = "dstflow"

seip = "seip" #seteip
stpeip = "stpeip" #stop eip

rep_mov_cmp =     [ 'movsb', 'movsw', 'movsd', 'cmpsb', 'cmpsw', 'cmpsd' ]
rep_sto_lod_sca = [ 'stosb', 'stosd', 'stosw', 'lodsb', 'lodsd', 'lodsw', 'scasb', 'scasd', 'scasw', ]
mnemo_prefetch = ['prefetcht0', 'prefetcht1', 'prefetcht2', 'prefetchnta', 'prefetchw', 'cmpxchg8b']
mnemo_sse_cmp_predicate = ['eq','lt','le','unord','neq','nlt','nle','ord']
mnemo_sse_cmp = ['cmp'+predicate+suffix
    for predicate in mnemo_sse_cmp_predicate
    for suffix in ['ps', 'pd', 'sd', 'ss'] ]

float_st_mnemo = ['fcomi','fcomip','fucomi','fucomip', 'fcmovb','fcmove','fcmovbe','fcmovu','fcmovnb','fcmovne','fcmovnbe','fcmovnu']
float_st_st1 =   ['fucom','fucomp','fxch']
float_arith_p =  ['faddp','fsubp','fmulp','fdivp','fsubrp','fdivrp']
float_arith =    ['fadd','fsub','fmul','fdiv','fsubr','fdivr','fcom','fcomp']

unsanity_mnemo = ['nop', 'monitor', 'mwait', 'fiadd', 'fcmovb', 'fcompp',
                  'fidivr', 'ficom', 'ficomp', 'fild', 'fist', 'fistp', 'fisttp',
                  'fld', 'fldcw', 'fld1', 'fldl2t', 'fldl2e', 'fldpi', 'fldlg2', 'fldln2', 'fldz', 'fldenv', 'fimul', 'fst', 'fstp', 'fnstcw', 'fnstenv', 'f2xm1',
                  'fnstsw', 'fisub', 'fisubr', 'ftst', 'fucompp', 'fxam', 'fxtract', 'fyl2x', 'fyl2xp1', 'fsqrt', 'fsincos', 'fsin', 'fscale',
                  'fcos', 'fdecstp', 'fincstp', 'fnop', 'fpatan', 'fprem', 'fprem1', 'fptan', 'frndint', 'shl', 'sal', 'sar', 'fabs',
                  'fldenv', 'fchs',
                  'ffree', 'ffreep',
                  'aad', 'aam',
                  'jmpff'] + float_st_mnemo + float_st_st1 + float_arith_p + float_arith


mask_drcrsg = {cr:0x100, dr:0x200, sg:0x400}

def hexdump(a):
    if type(a) == str: return ''.join(["%.2x"%ord(_) for _ in a])
    return ''.join(["%.2X"%x for x in a])

def is_address(a):
    if x86_afs.ad in a and a[x86_afs.ad]:
        return True
    return False

def is_imm(a):
    if x86_afs.ad in a and a[x86_afs.ad]:
        return False
    if not (x86_afs.imm in a or x86_afs.symb in a) :
        return False
    for k in a:
        if not k in [x86_afs.imm, x86_afs.size, x86_afs.ad, x86_afs.symb, 'txt']:
            return False
    return True

def is_ad_lookup(a):
    if not x86_afs.ad in a or not a[x86_afs.ad]:
        return False
    if not (x86_afs.imm in a or x86_afs.symb in a) :
        return False
    for k in a:
        if not k in [x86_afs.imm, x86_afs.size, x86_afs.ad, x86_afs.symb]:
            return False
    return True

def is_reg(a):
    if x86_afs.ad in a and a[x86_afs.ad]:
        return False
    if x86_afs.imm in a:
        return False
    if x86_afs.symb in a:
        return False

    return True

def get_label(a):
    if x86_afs.ad in a and a[x86_afs.ad]:
        return None
    if x86_afs.imm in a:
        return None
    if not x86_afs.symb in a:
        return None
    n = a[x86_afs.symb]
    if len(n)!=1:
        return None
    k = list(n.keys())[0]
    if n[k] != 1:
        return None
    return k


def imm_to_generic(imm):
    if hasattr(imm, 'reloc32'):
        return 0x12345678, 0x12345678, 0x12345678
    else:
        return int(imm), int32(uint32(imm)), int16(uint16(imm))

def ad_to_generic(a):
    out = []
    to_add = []
    #generic ad size
    if a[x86_afs.ad]:
        a[x86_afs.ad] = True
        if  x86_afs.imm in a:
            i, j, _ = imm_to_generic(a[x86_afs.imm])
            if 0 <= i <= 0xFF:
                to_add.append({x86_afs.imm:x86_afs.u08})
            if -128 <= j < 128:
                to_add.append({x86_afs.imm:x86_afs.s08})
        else:
            to_add.append({x86_afs.imm:x86_afs.u08})
            to_add.append({x86_afs.imm:x86_afs.s08})
        #imm can always be encoded in u32 ; this long encoding appears last
        to_add.append({x86_afs.imm:x86_afs.u32})
    if not x86_afs.imm in a:
        out.append(a)
    else:
        i, j, _ = imm_to_generic(a[x86_afs.imm])
        if i == 0:
            tmp = dict(a)
            del tmp[x86_afs.imm]
            out.append(tmp)
        if -128 <= j < 128:
            to_add.append({x86_afs.imm:x86_afs.s08})
        if 0 <= i <= 0xFF:
            to_add.append({x86_afs.imm:x86_afs.u08})
    for kv in to_add:
        tmp = dict(a)
        tmp.update(kv)
        out.append(tmp)
    out_unik = []
    for o in out:
        if not o in out_unik:
            out_unik.append(o)
    return out_unik

def check_imm_size(imm, size):
    i, j, k = imm_to_generic(imm)
    if not size in [u08, s08, u16, s16, u32, s32]:
        raise ValueError("unknown size %s"%size)
    elif size == u08 and -0x80 <= i < 0x100:
        return uint8(imm)
    elif size == s08 and -0x80 <= j < 0x80:
        return int8(imm)
    elif size == s08 and -0x80 <= k < 0x80 and getattr(imm, 'size', 0) == 16:
        return int8(int16(imm))
    elif size == u16 and 0 <= i < 0x10000:
        return uint16(imm)
    elif size == s16 and -0x8000 <= j < 0x8000:
        return int16(imm)
    elif size == u32 and -uint32.limit <= i < uint32.limit:
        return uint32(imm)
    elif size == s32 and -uint32.limit/2 <= j < uint32.limit/2:
        return int32(imm)
    return None

def add_imm_to_string(base, immediate, size, imm_format="%d"):
    immediate = int(immediate)
    if size in [x86_afs.u32, True] and immediate > 2**31:
        immediate -= 2**32
    if immediate < 0 or base == "":
        if immediate < 0:
            immediate = -immediate
            format = "%s-" + imm_format
        else:
            format = "%s" + imm_format
    else:
        format = "%s+" + imm_format
    return format % (base, immediate)

def get_reg_name(k, admode):
    if admode == u16:
        return x86_afs.reg_list16[k]
    return x86_afs.reg_list32[k]

def dict_to_ad(d, modifs = None, opmode = u32, admode = u32, asm_format='intel_syntax noprefix'):
    if asm_format.endswith("objdump"):
        imm_format = "%#x"
    else:
        imm_format = "%d"
    if modifs is None:
        modifs = dict([[x, None] for x in [w8, se, sw, ww, sg, dr, cr, ft, w64, sd, wd, bkf, spf, dtf, mmx]])
    size = [x86_afs.u32, x86_afs.u08][modifs[w8]==True]
    #overwrite w8
    if modifs[sd]!=None:
        size = [x86_afs.f32, x86_afs.f64][modifs[sd]==True]
    elif modifs[wd]:
        size = x86_afs.u16

    tab32 = {x86_afs.u08:x86_afs.reg_list8, x86_afs.u16:x86_afs.reg_list16, x86_afs.u32:x86_afs.reg_list32,x86_afs.f32:x86_afs.reg_flt, x86_afs.f64:x86_afs.reg_flt, x86_afs.mm:x86_afs.reg_mm, x86_afs.xmm:x86_afs.reg_xmm}
    tab16 = {x86_afs.u08:x86_afs.reg_list8, x86_afs.u16:x86_afs.reg_list32, x86_afs.u32:x86_afs.reg_list16}
    ad_size = {True:"", x86_afs.u08:"BYTE PTR ", x86_afs.u16:"WORD PTR ", x86_afs.u32:"DWORD PTR ", x86_afs.f80:"TBYTE PTR ", x86_afs.f32:"DWORD PTR ", x86_afs.f64:"QWORD PTR ", x86_afs.mm:"", x86_afs.xmm:"XMMWORD PTR "}
    
    if is_reg(d):
        n = [x for x in d if type(x) == int]
        if len(n)!=1:
            raise ValueError("bad reg! %s" % d)
        n = n[0]
        if x86_afs.size in d and d[x86_afs.size] == x86_afs.size_seg :
            t = x86_afs.reg_sg
        elif x86_afs.size in d:
            my_s = d[x86_afs.size]
            if my_s == x86_afs.f64:
                my_s = x86_afs.u32
            t = tab32[my_s]
        else:
            if opmode == u32:
                t = tab32[size]
            else:
                t = tab16[size]
        if modifs[dr] and n>0x7:
            t = x86_afs.reg_dr
            n&=7
        if modifs[cr] and n>0x7:
            t = x86_afs.reg_cr
            n&=7
        if modifs[sg] and n>0x7:
            t = x86_afs.reg_sg
            n&=7
        if modifs[sd] is not None:
            t = tab32[size]
            n&=7
        if modifs[mmx]:
            if 0 <= n-x86_afs.reg_mm_base < 8:
                t = x86_afs.reg_mm
            elif 0 <= n-x86_afs.reg_xmm_base < 8:
                t = x86_afs.reg_xmm
            n&=7

        try:
            out = t[n]
            if out.startswith('st'):
                out = "st(%s)" % out[2:]
            if not asm_format.endswith('noprefix'):
                out = '%'+out
        except ValueError:
            print('WARNING!dict2ad %s %s' %(t, d))
            out = ""
        return out
    elif is_imm(d):
        arg = d.copy()
        size      = arg.pop(x86_afs.size, x86_afs.u32)
        immediate = arg.pop(x86_afs.imm, None)
        symbol = []
        for s, c in arg.pop(x86_afs.symb, {}).items():
            if   c > 0: v = ["+"]
            elif c < 0: v = ["-"]
            if c in [1, -1]:  v.append(str(s))
            else: v.append("%d*%s"%(abs(c),s))
            if   c > 0: symbol[:0] = v
            elif c < 0: symbol.extend(v)
        if len(symbol) > 0 and symbol[0] == '+':
            symbol = symbol[1:]
        if len(symbol) == 3 and symbol[1] == '+' and symbol[2] == '_GLOBAL_OFFSET_TABLE_':
            # as 2.15 likes _GLOBAL_OFFSET_TABLE_+[.-.L10]
            # and fails on [.-.L10]+_GLOBAL_OFFSET_TABLE_
            symbol =[ symbol[2], symbol[1], symbol[0] ]
        out = ''.join(symbol)
        if out != '' and asm_format.startswith('intel_syntax') and not modifs['dstflow']:
            out = 'OFFSET FLAT:'+out
        if len(symbol) == 3 and symbol[1] == '+' and symbol[0] == '_GLOBAL_OFFSET_TABLE_' and asm_format.startswith('intel_syntax'):
            # special case of Intel syntax, without OFFSET FLAT:
            if not symbol[2].startswith('[.-.') and not symbol[2].endswith(']'):
                log.error("dict_to_ad on %r", d)
            else:
                symbol[2] = "(%s)" % symbol[2][1:-1]
                out = ''.join(symbol)
        if immediate != None:
            out = add_imm_to_string(out, immediate, size, imm_format=imm_format)
        if asm_format.startswith('att_syntax'):
            out = '$'+out
        return out
    elif is_address(d):
        arg = d.copy()
        del arg[x86_afs.ad]
        size      = arg.pop(x86_afs.size)
        size      = ad_size[size]
        if x86_afs.segm in arg:
            segment   = "%s:" % x86_afs.reg_sg[arg.pop(x86_afs.segm)]
            if not asm_format.endswith('noprefix'):
                segment = '%'+segment
        else:
            segment   = ""
        immediate = arg.pop(x86_afs.imm, None)
        symbol    = []
        for s, c in arg.pop(x86_afs.symb, {}).items():
            if   c > 0: v = ["+"]
            elif c < 0: v = ["-"]
            if c in [1, -1]:  v.append(str(s))
            else: v.append("%d*%s"%(abs(c),s))
            if   c > 0: symbol[:0] = v
            elif c < 0: symbol.extend(v)
        if len(symbol) > 0 and symbol[0] == '+':
            symbol = symbol[1:]
        symbol = "".join(symbol)
        txt       = arg.pop('txt', '')
        address = []
        for k in arg.values():
            if type(k) != int:
                raise ValueError('Invalid argument component in %s'%d)
        if len(arg.values()) == 0:
            pass
        elif len(arg.values()) == 1:
            k, c = arg.popitem()
            reg = get_reg_name(k, admode)
            if c == 1 and not txt.endswith("*1"):
                address.append(reg)
            elif c == 2 and txt.startswith(reg+"+"):
                log.info("Use + rather than 2*")
                address.append(reg)
                address.append(reg)
            elif c == 3:
                address.append(reg)
                address.append(reg)
                address.append(2)
            elif c == 5:
                address.append(reg)
                address.append(reg)
                address.append(4)
            elif c == 9:
                address.append(reg)
                address.append(reg)
                address.append(8)
            else:
                address.append(0)
                address.append(reg)
                address.append(c)
        elif len(arg.values()) == 2:
            # Find which register is first
            k = x86_afs.reg_list32.index(x86_afs.r_esp)
            if k in arg and admode == u32:
                c = arg.pop(k)
                if c != 1:
                    raise ValueError("esp multiplied by %d"%c)
            elif len(set(arg.values())) != 1:
                k = list(arg.keys())
                if arg[k[0]] == 1: k = k[0]
                else:              k = k[1]
                c = arg.pop(k)
                if c != 1:
                    raise ValueError('No registers without multiplier in %s'%d)
            else:
                # Order depends on 'txt', cf. below
                # We should move this re-ordering here
                k, c = arg.popitem()
            reg = get_reg_name(k, admode)
            address.append(reg)
            # The other one
            k, c = arg.popitem()
            reg = get_reg_name(k, admode)
            address.append(reg)
            if c != 1:
                address.append(c)
        else:
            raise ValueError('Too many registers appear in %s'%d)
        if len(address) == 2 and txt.startswith(address[1]+"+"):
            log.info("Swap operands")
            address[0:2] = [address[1],address[0]]
        if not asm_format.endswith('noprefix'):
            for idx, r in enumerate(address):
                if type(r) == str:
                    address[idx] = '%'+r
        if len(address) > 0:
            imm_size = x86_afs.u32
        else:
            imm_size = d[x86_afs.size]
        if asm_format.startswith('att_syntax'):
            if immediate != None and int(immediate) != 0:
                symbol = add_imm_to_string(symbol, immediate, imm_size, imm_format)
            if len(address) == 3:
                address[2]= str(address[2])
                if address[0] == 0:
                    address[0] = ''
                    if symbol == '':
                        symbol = '0'
            address = ",".join(address)
            if address != '':
                address = '('+address+')'
            if symbol+address == '':
                address = '0'
            return segment+symbol+address
        else:
            if len(address) == 3:
                address[1:3] = [ "%s*%d" % (address[1], address[2]) ]
                if address[0] == 0:
                    if immediate != None:
                        address[0] = add_imm_to_string("", immediate, imm_size)
                        immediate = 0
                    else:
                        address[0] = '0'
            address = "+".join(address)
            if immediate != None and int(immediate) != 0:
                if len(address) > 0:
                    address = add_imm_to_string(address,immediate, imm_size)
                else:
                    symbol  = add_imm_to_string(symbol, immediate, imm_size)
            if address != '':
                address = '['+address+']'
            if symbol+address == '':
                address = '0'
            return size+segment+symbol+address
    raise ValueError('unknown arg %s' % d)



class x86allmncs:
    def print_op(self, optab, decal):
        cpt = -1
        for i in optab:
            cpt+=1
            if type(i) == list:
                self.print_op(i, decal+1)
            elif i is None:
                pass
            else:
                print("%.3d "%cpt + "\t"*decal + str(i))

    def print_tab(self):
        for i in range(0x100):
            if type(self.db_afs[i]) == list:
                for j in range(0x100):
                    print("%.2X %.2X\t%s" % (i, j, self.db_afs[i][j]))
            else:
                print("%.2X\t%s" % (i, self.db_afs[i]))

    def get_afs(self, bin, m, size_m):
        if size_m == u16:
            db_afs = self.db_afs_16
            my_uint = uint16
        elif size_m == u32:
            db_afs = self.db_afs
            my_uint = uint32
        elif size_m == mm:
            db_afs = self.db_afs_mm
            my_uint = uint32
        elif size_m == xmm:
            db_afs = self.db_afs_xmm
            my_uint = uint32
        elif size_m == x86_afs.f64:
            db_afs = self.db_afs
            my_uint = uint32

        mod, re, rm = self.modrm(m)

        if type(db_afs[m])==list:
            a = dict(db_afs[m][ord(bin.readbs())])
        else:
            a = dict(db_afs[m])
        if x86_afs.imm in a:
            if a[x86_afs.imm] == x86_afs.u08:
                a[x86_afs.imm] = my_uint(struct.unpack('B', bin.readbs())[0])
            elif a[x86_afs.imm] == x86_afs.s08:
                a[x86_afs.imm] = my_uint(struct.unpack('b', bin.readbs())[0])
            elif a[x86_afs.imm] == x86_afs.u32:
                a[x86_afs.imm] = my_uint(struct.unpack('I', bin.readbs(4))[0])
            elif a[x86_afs.imm] == x86_afs.u16:
                a[x86_afs.imm] = my_uint(struct.unpack('H', bin.readbs(2))[0])
            else:
                raise ValueError('imple other afs ... %s' % a[x86_afs.imm])
        return re, a

    def get_afs_re(self, re):
        return {x86_afs.ad:False, re:1}

    def get_im_fmt(self, modifs, mnemo_mode, im):
        if modifs[se]:
            fmt,t = ('b',s08)
        elif modifs[w8]:
            if im == imm:
                fmt,t = ('B',u08)
            elif im == ims:
                fmt,t = ('b',s08)
            else:
                raise ValueError("error encode %s" % im)
        else:
            if im == imm:
                if mnemo_mode == u32: fmt,t = ('I',u32)
                else:                 fmt,t = ('H',u16)
            elif im == ims:
                if mnemo_mode == u32: fmt,t = ('i',s32)
                else:                 fmt,t = ('h',s16)
            else:
                raise ValueError("error encode %s" % im)


        return struct.calcsize(fmt), fmt,t

    def modrm(self, c):
        return (c>>6)&3, (c>>3)&7, c&7
    def sib(self, c):
        return self.modrm(c)

    def modrm_key(self, dictionary):
        return sorted(dictionary.items(), key=str)

    def init_pre_modrm(self):

        self.sib_rez_u08_ebp = [{x86_afs.ad:True} for i in range(0x100)]
        self.sib_rez_u32_ebp = [{x86_afs.ad:True} for i in range(0x100)]
        self.sib_rez_u32 = [{x86_afs.ad:True} for i in range(0x100)]

        for sib_rez in [self.sib_rez_u08_ebp,
                        self.sib_rez_u32_ebp,
                        self.sib_rez_u32
                        ]:
            for index in range(0x100):
                ss, i, r = self.modrm(index)
                sib_rez[index]['txt'] = []
                # Primary register
                if r != 5 or sib_rez != self.sib_rez_u32:
                    sib_rez[index][r] = 1
                    sib_rez[index]['txt'].append(x86_afs.reg_list32[r])
                # Secondary register
                if i != 4:
                    if not i in sib_rez[index]:
                        sib_rez[index][i] = 0
                    sib_rez[index][i] += 2**ss
                    sib_rez[index]['txt'].append(x86_afs.reg_list32[i])
                elif ss > 0:
                    # eiz (named by objdump) is a pseudo-register
                    # that helps to represent a non-zero 'ss' scale
                    sib_rez[index]['txt'].append("eiz")
                if ss > 0:
                    sib_rez[index]['txt'][-1] += "*%d"%(2**ss)

                # Type of immediate
                if sib_rez == self.sib_rez_u08_ebp:
                    sib_rez[index][x86_afs.imm] = x86_afs.s08
                elif sib_rez == self.sib_rez_u32_ebp:
                    sib_rez[index][x86_afs.imm] = x86_afs.u32
                elif sib_rez == self.sib_rez_u32 and r == 5:
                    sib_rez[index][x86_afs.imm] = x86_afs.u32
                else: # u32 and r != 5
                    pass # No immediate
                if r == 5 or sib_rez != self.sib_rez_u32:
                    sib_rez[index]['txt'].append("imm")
                sib_rez[index]['txt'] = '+'.join(sib_rez[index]['txt'])

        #32bit
        self.db_afs = [None for i in range(0x100)]
        for i in range(0x100):
            mod, re, rm = self.modrm(i)
            if mod == 3:
                self.db_afs[i] = {x86_afs.ad:False, rm:1}
            elif rm == 4:
                if mod == 0:
                    self.db_afs[i] = self.sib_rez_u32
                elif mod == 1:
                    self.db_afs[i] = self.sib_rez_u08_ebp
                elif mod == 2:
                    self.db_afs[i] = self.sib_rez_u32_ebp
            elif mod == 2: # rm != 4
                self.db_afs[i] = {x86_afs.ad:True, rm:1,x86_afs.imm:x86_afs.u32}
                self.db_afs[i]['txt'] = x86_afs.reg_list32[rm]+'+imm'
            elif mod == 1: # rm != 4
                self.db_afs[i] = {x86_afs.ad:True, rm:1,x86_afs.imm:x86_afs.s08}
                self.db_afs[i]['txt'] = x86_afs.reg_list32[rm]+'+imm'
            elif rm == 5: # mod == 0
                self.db_afs[i] = {x86_afs.ad:True, x86_afs.imm:x86_afs.u32}
                self.db_afs[i]['txt'] = 'imm'
            else: # mod == 0, rm != 4, 5
                self.db_afs[i] = {x86_afs.ad:True, rm:1}
                self.db_afs[i]['txt'] = x86_afs.reg_list32[rm]

        # Precomputation of db_afs lookup
        self.fd_afs = {}
        for i in range(0x100):
            index = i&0xC7
            if type(self.db_afs[index])==list:
                for j in range(0x100):
                    ad = tuple(self.modrm_key(self.db_afs[index][j]))
                    if not ad in self.fd_afs:
                        self.fd_afs[ad] = []
                    if not (index, j)  in self.fd_afs[ad]:
                        self.fd_afs[ad].append((index, j) )
            else:
                ad = tuple(self.modrm_key(self.db_afs[index]))
                if not ad in self.fd_afs:
                    self.fd_afs[ad] = []
                if not (index, None)  in self.fd_afs[ad]:
                    self.fd_afs[ad].insert(0, (index, None) )
        for i in range(0x100):
            index = i&0xC7
            if type(self.db_afs[index])==list:
                for j in range(0x100):
                    ad = self.modrm_key(self.db_afs[index][j])
                    ad = tuple([ (x, y) for (x, y) in ad if x != 'txt' ])
                    if not ad in self.fd_afs:
                        self.fd_afs[ad] = []
                    if not (index, j)  in self.fd_afs[ad]:
                        self.fd_afs[ad].append((index, j) )
            else:
                ad = self.modrm_key(self.db_afs[index])
                ad = tuple([ (x, y) for (x, y) in ad if x != 'txt' ])
                if not ad in self.fd_afs:
                    self.fd_afs[ad] = []
                if not (index, None)  in self.fd_afs[ad]:
                    self.fd_afs[ad].insert(0, (index, None) )

        #MMX
        self.db_afs_mm = [self.db_afs[i] for i in range(0x100)]
        self.db_afs_xmm = [self.db_afs[i] for i in range(0x100)]
        for i in range(0xc0,0x100):
            # MM
            ad = {x86_afs.ad:False, x86_afs.reg_mm_base+(i%8):1}
            self.db_afs_mm[i] = ad
            ad = tuple(self.modrm_key(ad))
            if not ad in self.fd_afs:
                self.fd_afs[ad] = []
            self.fd_afs[ad].append((i, None))
            # XMM
            ad = {x86_afs.ad:False, x86_afs.reg_xmm_base+(i%8):1}
            self.db_afs_xmm[i] = ad
            ad = tuple(self.modrm_key(ad))
            if not ad in self.fd_afs:
                self.fd_afs[ad] = []
            self.fd_afs[ad].append((i, None))

        #16bit
        self.db_afs_16 = [None for i in range(0x100)]
        _si = x86_afs.reg_dict[x86_afs.r_si]
        _di = x86_afs.reg_dict[x86_afs.r_di]
        _bx = x86_afs.reg_dict[x86_afs.r_bx]
        _bp = x86_afs.reg_dict[x86_afs.r_bp]
        for i in range(0x100):
            index = i
            mod, re, rm = self.modrm(i)

            if mod == 0:
                if rm == 4:
                    self.db_afs_16[index] = {x86_afs.ad:True,_si:1}
                elif rm == 5:
                    self.db_afs_16[index] = {x86_afs.ad:True,_di:1}
                elif rm == 6:
                    self.db_afs_16[index] = {x86_afs.ad:True,x86_afs.imm:x86_afs.u16}#{x86_afs.ad:True,_bp:1}
                elif rm == 7:
                    self.db_afs_16[index] = {x86_afs.ad:True,_bx:1}
                else:
                    self.db_afs_16[index] = {x86_afs.ad:True,
                                             [_si, _di][rm%2]:1,
                                             [_bx, _bp][(rm>>1)%2]:1}
            elif mod in [1,2]:
                if mod==1:
                    if rm==0:
                        my_imm=x86_afs.s08
                    else:
                        my_imm=x86_afs.s08
                else:
                    my_imm=x86_afs.u16

                if rm==4:
                    self.db_afs_16[index] = {x86_afs.ad:True,_si:1, x86_afs.imm:my_imm}
                elif rm==5:
                    self.db_afs_16[index] = {x86_afs.ad:True,_di:1, x86_afs.imm:my_imm}
                elif rm==6:
                    self.db_afs_16[index] = {x86_afs.ad:True,_bp:1, x86_afs.imm:my_imm}
                elif rm==7:
                    self.db_afs_16[index] = {x86_afs.ad:True,_bx:1, x86_afs.imm:my_imm}
                else:
                    self.db_afs_16[index] = {x86_afs.ad:True,
                                             [_si, _di][rm%2]:1,
                                             [_bx, _bp][(rm>>1)%2]:1,
                                             x86_afs.imm:my_imm}

            elif mod == 3:
                self.db_afs_16[index] = {x86_afs.ad:False, rm:1}


    def addop(self, name, opc, afs, rm, modif_desc, prop_dict, sem):
        prop_dict.update(sem)
        modifs = dict([[x, True] for x in modif_desc])
        base_modif = dict([[x, None] for x in [w8, se, sw, ww, sg, dr, cr, ft, w64, sd, wd, bkf, spf, dtf, mmx]])
        base_modif.update(modifs)

        #update with forced properties
        base_modif.update(prop_dict)
        base_mnemo = [(opc, base_modif)]

        if se in modif_desc:
            # First in list has se=True
            base_mnemo[0][0][modif_desc[se][0]] ^= 1<<modif_desc[se][1]

        log.debug(modifs)
        for modif in modifs:
            base_mnemo_add = []
            for opc, n_m in base_mnemo:
                n_m = dict(n_m)
                n_m[modif]= not n_m[modif]

                opc = opc[:]
                opc[modif_desc[modif][0]] ^=(1<<modif_desc[modif][1])

                base_mnemo_add.append((opc, n_m))

            base_mnemo+=base_mnemo_add

        for opc, n_m in base_mnemo:
            #unassociable modifs XXX here cause structure generation
            if n_m[se] and n_m[w8]:
                continue

            if afs in [d0, d1, d2, d3, d4, d5, d6, d7]:
                opc+=[afs]
                mask = mask_d
            elif afs in [reg]:
                mask = mask_reg
            elif afs == noafs:
                mask = 0xFF
            elif afs == cond:
                mask = mask_cond
            else:
                raise ValueError('bug in %s %d'%(name, afs))

            #finit is wait;fninit: special treatment
            if name == "finit":
                mnemo = mnemonic(name, opc, afs, rm, n_m, modif_desc, sem)
                self.mnemo_lookup[mnemo.name] = [mnemo]
                return
            #find mnemonic table
            insert_tab = self.db_mnemo
            log.debug(name)
            log.debug(opc )
            log.debug(mask)
            for i in opc[:-1]:
                if insert_tab[i] is None:
                    insert_tab[i] = [None for x in range(0x100)]
                insert_tab = insert_tab[i]

            keys = mask_opc_to_i(mask, opc[-1])
            if afs == cond:
                for k in keys:
                    opc_tmp = opc[:]
                    i_k = k&(mask_cond^0xFF)
                    opc_tmp[-1]|=i_k
                    for cond_suffix in cond_list[i_k]:
                        mnemo = mnemonic(name+cond_suffix, opc_tmp, afs, rm, n_m, modif_desc, sem)
                        #if insert_tab[k]!=None and not name in unsanity_mnemo:
                        #    raise ValueError("sanity check fail in mnemo affect %s" % insert_tab[k])
                        insert_tab[k] = mnemo
                        #fast mnemo_lookup
                        if not mnemo.name in self.mnemo_lookup:
                            self.mnemo_lookup[mnemo.name] = [mnemo]
                        elif not mnemo in self.mnemo_lookup[mnemo.name]:
                            self.mnemo_lookup[mnemo.name].append(mnemo)

            else:
                mnemo = mnemonic(name, opc, afs, rm, n_m, modif_desc, sem)
                for k in keys:
                    if insert_tab[k]!=None and not name in unsanity_mnemo:
                        raise ValueError("sanity check fail in mnemo %r affect %s" % (name, insert_tab[k]))
                    insert_tab[k] = mnemo
                    #fast mnemo_lookup
                    if not mnemo.name in self.mnemo_lookup:
                        self.mnemo_lookup[mnemo.name] = [mnemo]
                    elif not mnemo in self.mnemo_lookup[mnemo.name]:
                        self.mnemo_lookup[mnemo.name].append(mnemo)

    def find_mnemo(self, name, mnemo_list = None, candidate = None):
        if name in self.mnemo_lookup.keys():
            return self.mnemo_lookup[name]
        else:
            return []


    def forge_opc(self, out_opc, a, a2 = None):
        if a2!=None :
            k = [x for x in a2.keys() if type(x) == int]
            if a2[x86_afs.ad] or x86_afs.imm in a2 or len(k)!=1:
                raise ValueError('bad a2 forge %s' % a2)
            out_opc[0].append((k[0]&7)<<3)

        #if not a[x86_afs.ad]:
        del a[x86_afs.size]

        if a.get('txt','').count('+') == 2:
            # reg+reg+imm or reg+imm+reg => delete imm to keep register order
            a['txt'] = '+'.join(
                [_ for _ in a['txt'].split('+') if not _[0] in '0123456789'])
        log.debug("forge_opc a=%s", a)
        # Find all possible opcodes, first the ones that preserve arg order
        order_ok = []
        order_ko = []
        for ad in ad_to_generic(a):
            key_ok = tuple(self.modrm_key(ad))
            raw_ok = self.fd_afs.get(key_ok, [])
            if not raw_ok and 'txt' in ad:
                # when asking for rA+rB, prefer rA+rB+imm to rB+rA
                # this is what does e.g. GNU as 2.22
                ad = dict(ad)
                ad['txt'] += '+imm'
                key_ok = tuple(self.modrm_key(ad))
                raw_ok = self.fd_afs.get(key_ok, [])
            key_ko = tuple([ (x, y) for (x, y) in key_ok if x != 'txt' ])
            raw_ko = self.fd_afs.get(key_ko, [])
            raw_ko = [ _ for _ in raw_ko if not _ in raw_ok ]
            if raw_ok: order_ok.append( (ad, raw_ok) )
            if raw_ko: order_ko.append( (ad, raw_ko) )
            log.debug("get_address_afs_hex %s", key_ok)

        out = []
        for ad, rlist in order_ok+order_ko:
            log.debug("forge_opc %s", ad)
            p = {}
            if x86_afs.imm in ad:
                v = check_imm_size(a.get(x86_afs.imm, 0), ad[x86_afs.imm])
                if v is None:
                    log.debug("cannot encode this val in size forge!")
                    return None, None
                p = {x86_afs.size:ad[x86_afs.imm], x86_afs.imm:v, x86_afs.ad:ad[x86_afs.ad]}
            for r in rlist:
                opc = out_opc[0][:]
                opc[-1] |= r[0]
                if r[1]is not None:
                    opc.append(r[1])
                out.append( (opc, p) )

        log.debug("forge_opc => %r", out)
        if out == []: return [], [] # zip returns only one list
        return [list(_) for _ in zip(*out)]

    def check_size_modif(self, size, modifs):
        if modifs[sd] is not None:
            if   modifs[sd] == False  and size in [x86_afs.u64,x86_afs.f64]:
                return True
            elif modifs[sd] == True   and size in [x86_afs.f32]:
                return True
            elif modifs[sd] == 'fp80' and size in [x86_afs.f80]:
                return True
            else:
                log.debug('checksize: not good fXX (%s)', size)
                return False
        if modifs[wd] is not None:
            if size != [x86_afs.u32, x86_afs.u16][modifs[wd]]:
                log.debug('checksize: not good w/dw')
                return False
            else:
                return True
        if modifs[mmx] is not None:
            if not size in [x86_afs.u32, x86_afs.mm, x86_afs.xmm]:
                log.debug('checksize: not good MMX %s %s', size, modifs)
                return False
            else:
                return True
        if size != [x86_afs.u32, x86_afs.u08][modifs[w8]==True]:
            log.debug('checksize: not good w8:%s', size)
            return False
        return True


    def __init__(self):

        self.mnemo_lookup = {}
        self.init_pre_modrm()
        self.op_db = {}

        self.db_mnemo = [None for x in range(0x100)]
        addop = self.addop


        #x86

        addop("aaa",   [0x37],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("aad",   [0xD5],             noafs, [u08]         , {}                 ,{}                , {},                         )
        addop("aam",   [0xD4],             noafs, [u08]         , {}                 ,{}                , {},                         )

        addop("aas",   [0x3F],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("adc",   [0x82],             d2,    [imm]         , {w8:(0,0)}         ,{se:True}         , {},                         )
        addop("adc",   [0x14],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("adc",   [0x80],             d2,    [imm]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("adc",   [0x10],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("add",   [0x82],             d0,    [imm]         , {w8:(0,0)}         ,{se:True}         , {},                         )
        addop("add",   [0x04],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("add",   [0x80],             d0,    [imm]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("add",   [0x00],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("and",   [0x82],             d4,    [imm]         , {w8:(0,0)}         ,{w8:True,se:True} , {},                         )
        addop("and",   [0x24],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("and",   [0x80],             d4,    [imm]         , {w8:(0,0)}         ,{w8:True}         , {},                         )
        addop("and",   [0x20],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("arpl",  [0x63],             noafs, [rmr]         , {}                 ,{sw:True,wd:True} , {},                         )

        addop("bound", [0x62],             noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("bsf",   [0x0F, 0xBC],       noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("bsr",   [0x0F, 0xBD],       noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("bswap", [0x0F, 0xC8],       reg  , no_rm         , {}                 ,{}                , {},                         )

        addop("bt",    [0x0F, 0xA3],       noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )
        addop("bt",    [0x0F, 0xBA],       d4   , [u08]         , {}                 ,{}                , {},                         )
        addop("btc",   [0x0F, 0xBB],       noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )
        addop("btc",   [0x0F, 0xBA],       d7   , [u08]         , {}                 ,{}                , {},                         )
        addop("btr",   [0x0F, 0xB3],       noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )
        addop("btr",   [0x0F, 0xBA],       d6   , [u08]         , {}                 ,{}                , {},                         )
        addop("bts",   [0x0F, 0xAB],       noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )
        addop("bts",   [0x0F, 0xBA],       d5   , [u08]         , {}                 ,{}                , {},                         )

        addop("call",  [0xE8],             noafs, [s32]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("call",  [0xFF],             d2   , no_rm         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("call",  [0x9A],             noafs, [imm,u16]     , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("callf", [0xFF],             d3,    no_rm         , {}                 ,{}                , {bkf:True,spf:True,dtf:True}) #XXX

        addop("cbw",   [0x66, 0x98],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("cwde",  [0x98],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("clc",   [0xF8],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("cld",   [0xFC],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("cli",   [0xFA],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("clts",  [0x0F, 0x06],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("cmc",   [0xF5],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("cmov",  [0x0F, 0x40],       cond , [rmr]         , {}                 ,{}                , {},                         )

        addop("cmp",   [0x82],             d7,    [imm]         , {w8:(0,0)}         ,{se:True}         , {},                         )
        addop("cmp",   [0x3C],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("cmp",   [0x80],             d7,    [imm]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("cmp",   [0x38],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("cmpsb", [0xA6],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        addop("cmpsd", [0xA7],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )
        addop("cmpsw", [0x66, 0xA7],       noafs, no_rm         , {}                 ,{w8:False}        , {},                         )


        addop("cmpxchg",[0x0F, 0xB0],      noafs, [rmr]         , {w8:(1,0)}         ,{sw:True}         , {},                         )
        addop("cmpxchg8b",[0x0F, 0xC7],    d1   , no_rm         , {}                 ,{}                , {},                         )
        addop("rdrand",[0x0F, 0xC7],       d6   , no_rm         , {}                 ,{}                , {},                         )
        addop("cpuid", [0x0F, 0xA2],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("cwd",   [0x66, 0x99],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("cdq",   [0x99],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("daa",   [0x27],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("das",   [0x2F],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("dec",   [0x48],             reg  , no_rm         , {}                 ,{}                , {},                         )
        addop("dec",   [0xFE],             d1   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )
        addop("div",   [0xF6],             d6   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("enter", [0xC8],             noafs, [u16, u08]    , {}                 ,{}                , {},                         )

        addop("hlt",   [0xF4],             noafs, no_rm         , {}                 ,{}                , {bkf:True}                  )

        addop("idiv",  [0xF6],             d7   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("imul",  [0xF6],             d5   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )
        addop("imul",  [0x0F, 0xAF],       noafs, [rmr]         , {}                 ,{sw:False}        , {},                         )
        addop("imul",  [0x69],             noafs, [rmr, imm]    , {se:(0,1)}         ,{sw:False}        , {},                         )

        addop("in",    [0xE4],             noafs, [r_eax, u08]  , {w8:(0,0)}         ,{}                , {},                         )
        addop("in",    [0xEC],             noafs, [r_eax,r_dx]  , {w8:(0,0)}         ,{}                , {},                         )

        addop("inc",   [0x40],             reg  , no_rm         , {}                 ,{}                , {},                         )
        addop("inc",   [0xFE],             d0   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("ins",   [0x6C],             noafs, no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("int",   [0xCC],             noafs, [im3]         , {}                 ,{}                , {},                         )
        addop("int",   [0xCD],             noafs, [u08]         , {}                 ,{}                , {},                         )

        addop("into",  [0xCE],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("invd",  [0x0F, 0x08],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("invlpg",[0x0F, 0x01],       d7   , no_rm         , {}                 ,{}                , {},                         )

        addop("iret",  [0xCF],             noafs, no_rm         , {}                 ,{}                , {bkf:True}                  )

        addop("j",     [0x70],             cond , [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("j",     [0x0F, 0x80],       cond , [s32]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("jecxz", [0xE3],             noafs, [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})

        addop("jmp",   [0xE9],             noafs, [ims]         , {w8:(0,1)}         ,{w8:False}        , {bkf:True,dtf:True}         )
        addop("jmpf",  [0xEA],             noafs, [ims,u16]     , {}                 ,{}                , {bkf:True,dtf:True}         )
        addop("jmp",   [0xFF],             d4   , no_rm         , {}                 ,{}                , {bkf:True,dtf:True}         )
        addop("jmpf",  [0xFF],             d5   , no_rm         , {}                 ,{}                , {bkf:True,dtf:True}         )

        addop("lahf",  [0x9F],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("lar",   [0x0F, 0x02],       noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("ldmxcsr",[0x0F, 0xAE],      d2   , no_rm         , {}                 ,{}                , {},                         )
        addop("lds",   [0xC5],             noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("lss",   [0x0F, 0xB2],       noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("les",   [0xC4],             noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("lfs",   [0x0F, 0xB4],       noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("lgs",   [0x0F, 0xB5],       noafs, [rmr]         , {}                 ,{}                , {},                         )

        addop("lea",   [0x8D],             noafs, [rmr]         , {}                 ,{}                , {},                         )

        addop("leave", [0xC9],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("lgdt",  [0x0F, 0x01],       d2   , no_rm         , {}                 ,{}                , {},                         )
        addop("lidt",  [0x0F, 0x01],       d3   , no_rm         , {}                 ,{}                , {},                         )
        addop("lldt",  [0x0F, 0x00],       d2   , no_rm         , {}                 ,{}                , {},                         )
        addop("lmsw",  [0x0F, 0x01],       d6   , no_rm         , {}                 ,{}                , {},                         )

        #ddop("lods",  [0xAC],             noafs, no_rm         , {w8:(0,0)}         ,{}                , {},                         )
        addop("lodsb", [0xAC],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        addop("lodsd", [0xAD],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )
        addop("lodsw", [0x66, 0xAD],       noafs, no_rm         , {}                 ,{w8:False}        , {},                         )

        addop("loop",  [0xE2],             noafs, [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("loope", [0xE1],             noafs, [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("loopne",[0xE0],             noafs, [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})

        addop("lsl",   [0x0F, 0x03],       noafs, [rmr]         , {}                 ,{}                , {},                         )

        addop("ltr",   [0x0F, 0x00],       d3   , no_rm         , {}                 ,{wd:True}         , {},                         )


        addop("mov",   [0xA0],             noafs, [r_eax,mim]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("mov",   [0xA2],             noafs, [mim,r_eax]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("mov",   [0x88],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("mov",   [0xB0],             reg  , [imm]         , {w8:(0,3)}         ,{}                , {},                         )
        addop("mov",   [0x0F, 0x20],       noafs, [rmr]         , {sw:(1,1)}         ,{cr:True}         , {},                         )
        addop("mov",   [0x0F, 0x21],       noafs, [rmr]         , {sw:(1,1)}         ,{dr:True}         , {},                         )
        addop("mov",   [0x8C],             noafs, [rmr]         , {sw:(0,1)}         ,{sg:True,sw:True} , {},                         )
        addop("mov",   [0xC6],             d0   , [imm]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("movnti",[0x0F, 0xC3],       noafs, [rmr]         , {}                 ,{sw:True}                , {},                         )

        addop("movsb", [0xA4],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        # Note that the MMX movsd is renamed "mov#ups#"
        addop("movsd", [0xA5],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )
        addop("movsw", [0x66, 0xA5],       noafs, no_rm         , {}                 ,{w8:False}        , {},                         )
        addop("movsx", [0x0F, 0xBE],       noafs, [rmr]         , {se:(1,0)}         ,{}                , {},                         )
        addop("movzx", [0x0F, 0xB6],       noafs, [rmr]         , {se:(1,0)}         ,{}                , {},                         )

        addop("mul",   [0xF6],             d4   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("neg",   [0xF6],             d3   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )
        addop("nop",   [0x0F, 0x1F],       d0   , no_rm         , {}                 ,{}                , {},                         )
        addop("not",   [0xF6],             d2   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("or",    [0x82],             d1,    [imm]         , {w8:(0,0)}         ,{se:True}         , {},                         )
        addop("or",    [0x0C],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("or",    [0x80],             d1,    [imm]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("or",    [0x08],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("out",   [0xE6],             noafs, [u08,r_eax]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("out",   [0xEE],             noafs, [r_dx,r_eax]  , {w8:(0,0)}         ,{}                , {},                         )
        addop("outs",  [0x6E],             noafs, no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("pause", [0xF3, 0x90],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("pop",   [0x58],             reg  , no_rm         , {}                 ,{}                , {},                         )
        addop("pop",   [0x8F],             d0   , no_rm         , {}                 ,{}                , {},                         )
        addop("popad", [0x61],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("popfd", [0x9D],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("pop",   [0x07],             noafs, [r_es]        , {}                 ,{sg:True,}        , {},                         )
        addop("pop",   [0x17],             noafs, [r_ss]        , {}                 ,{sg:True,}        , {},                         )
        addop("pop",   [0x1f],             noafs, [r_ds]        , {}                 ,{sg:True,}        , {},                         )

        addop("pop",   [0x0F, 0xa1],       noafs, [r_fs]        , {}                 ,{sg:True,}        , {},                         )
        addop("pop",   [0x0F, 0xa9],       noafs, [r_gs]        , {}                 ,{sg:True,}        , {},                         )

        addop("prefetchnta",[0x0F, 0x18],  d0   , no_rm         , {}                 ,{}                , {},                         )
        addop("prefetcht0", [0x0F, 0x18],  d1   , no_rm         , {}                 ,{}                , {},                         )
        addop("prefetcht1", [0x0F, 0x18],  d2   , no_rm         , {}                 ,{}                , {},                         )
        addop("prefetcht2", [0x0F, 0x18],  d3   , no_rm         , {}                 ,{}                , {},                         )
        addop("prefetchw",  [0x0F, 0x0D],  d1   , no_rm         , {}                 ,{}                , {},                         )

        addop("push",  [0x68],             noafs, [imm]         , {se:(0,1)}         ,{}                , {},                         )
        addop("push",  [0x50],             reg  , no_rm         , {}                 ,{}                , {},                         )
        addop("push",  [0xFF],             d6   , no_rm         , {}                 ,{}                , {},                         )
        addop("pushad",[0x60],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("pushfd",[0x9C],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("push",  [0x0E],             noafs, [r_cs]        , {}                 ,{sg:True,}        , {},                         )
        addop("push",  [0x06],             noafs, [r_es]        , {}                 ,{sg:True,}        , {},                         )
        addop("push",  [0x16],             noafs, [r_ss]        , {}                 ,{sg:True,}        , {},                         )
        addop("push",  [0x1E],             noafs, [r_ds]        , {}                 ,{sg:True,}        , {},                         )

        addop("push",  [0x0F, 0xa0],       noafs, [r_fs]        , {}                 ,{sg:True,}        , {},                         )
        addop("push",  [0x0F, 0xa8],       noafs, [r_gs]        , {}                 ,{sg:True,}        , {},                         )

        addop("rcl",   [0xD0],             d2   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("rcl",   [0xD2],             d2   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("rcl",   [0xC0],             d2   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("rcr",   [0xD0],             d3   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("rcr",   [0xD2],             d3   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("rcr",   [0xC0],             d3   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("rol",   [0xD0],             d0   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("rol",   [0xD2],             d0   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("rol",   [0xC0],             d0   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("ror",   [0xD0],             d1   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("ror",   [0xD2],             d1   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("ror",   [0xC0],             d1   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("rdmsr", [0x0F, 0x32],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("rdpmc", [0x0F, 0x33],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("rdtsc", [0x0F, 0x31],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("ret",   [0xC3],             noafs, no_rm         , {}                 ,{}                , {bkf:True}                  )
        addop("retf",  [0xCB],             noafs, no_rm         , {}                 ,{}                , {bkf:True},                 )

        addop("ret",   [0xC2],             noafs, [u16]         , {}                 ,{}                , {bkf:True},                 )
        addop("retf",  [0xCA],             noafs, [u16]         , {}                 ,{}                , {bkf:True},                 )

        addop("rms",   [0x0F, 0xAA],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("sahf",  [0x9E],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("sar",   [0xD0],             d7   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("sar",   [0xD2],             d7   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sar",   [0xC0],             d7   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("shl",   [0xD0],             d4   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("shl",   [0xD2],             d4   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("shl",   [0xC0],             d4   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("sal",   [0xD0],             d4   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("sal",   [0xD2],             d4   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sal",   [0xC0],             d4   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("shr",   [0xD0],             d5   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("shr",   [0xD2],             d5   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("shr",   [0xC0],             d5   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("sbb",   [0x82],             d3,    [imm]         , {w8:(0,0)}         ,{se:True}         , {},                         )
        addop("sbb",   [0x1C],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("sbb",   [0x80],             d3,    [imm]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("sbb",   [0x18],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("scasb", [0xAE],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        addop("scasd", [0xAF],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )
        addop("scasw", [0x66, 0xAF],       noafs, no_rm         , {}                 ,{w8:False}        , {},                         )


        addop("set",   [0x0F, 0x90],       cond , [rmr]         , {}                 ,{w8:True}         , {},                         )

        addop("setalc",[0xd6],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("sgdt",  [0x0F, 0x01],       d0   , no_rm         , {}                 ,{}                , {},                         )

        addop("shld",  [0x0F, 0xA4],       noafs, [rmr, u08]    , {}                 ,{sw:True}         , {},                         )
        addop("shld",  [0x0F, 0xA5],       noafs, [rmr, r_cl]   , {}                 ,{sw:True}         , {},                         )
        addop("shrd",  [0x0F, 0xAC],       noafs, [rmr, u08]    , {}                 ,{sw:True}         , {},                         )
        addop("shrd",  [0x0F, 0xAD],       noafs, [rmr, r_cl]   , {}                 ,{sw:True}         , {},                         )

        addop("sidt",  [0x0F, 0x01],       d1   , no_rm         , {}                 ,{}                , {},                         )
        addop("sldt",  [0x0F, 0x00],       d0   , no_rm         , {}                 ,{}                , {},                         )
        addop("smsw",  [0x0F, 0x01],       d4   , no_rm         , {}                 ,{}                , {},                         )
        addop("stc",   [0xF9],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("std",   [0xFD],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("sti",   [0xFB],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("stmxcsr",[0x0F, 0xAE],      d3   , no_rm         , {}                 ,{}                , {},                         )

        addop("stosb", [0xAA],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        addop("stosd", [0xAB],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )
        addop("stosw", [0x66, 0xAB],       noafs, no_rm         , {}                 ,{w8:False}        , {},                         )

        addop("str",   [0x0F, 0x00],       d1   , no_rm         , {}                 ,{}                , {},                         )

        addop("sub",   [0x82],             d5,    [imm]         , {w8:(0,0)}         ,{se:True}         , {},                         )
        addop("sub",   [0x2C],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("sub",   [0x80],             d5,    [imm]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("sub",   [0x28],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        """                                                                                             , {}
        #XXX dup opcode => modrm encoding                                                               , {}
        addop("swapgs",[0x0F, 0x01],       d7   , no_rm         , {}                 ,{}                , {},                         )
        """                                                                                             , {}
        addop("syscall",[0x0F, 0x05],      noafs, no_rm         , {}                 ,{}                , {bkf:True},                 )
        addop("sysenter",[0x0F, 0x34],     noafs, no_rm         , {}                 ,{}                , {bkf:True},                 )
        addop("sysexit",[0x0F, 0x35],      noafs, no_rm         , {}                 ,{}                , {bkf:True},                 )
        addop("sysret",[0x0F, 0x07],       noafs, no_rm         , {}                 ,{}                , {bkf:True},                 )

        addop("test",  [0xA8],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("test",  [0xF6],             d0,    [imm]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("test",  [0x84],             noafs, [rmr]         , {w8:(0,0)}         ,{sw:True}         , {},                         )

        addop("ud2",   [0x0F, 0x0B],       noafs, no_rm         , {}                 ,{}                , {bkf:True}                  )
        addop("verr",  [0x0F, 0x00],       d4   , no_rm         , {}                 ,{}                , {},                         )
        addop("verw",  [0x0F, 0x00],       d5   , no_rm         , {}                 ,{}                , {},                         )
        addop("wbinvd",[0x0F, 0x09],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("wrmsr", [0x0F, 0x30],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("xadd",  [0x0F, 0xC0],       noafs, [rmr]         , {w8:(1,0)}         ,{sw:True}         , {},                         )

        addop("xchg",  [0x90],             reg  , [r_eax]       , {}                 ,{}                , {},                         )

        addop("nop",   [0x90],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("xchg",  [0x86],             noafs, [rmr]         , {w8:(0,0)}         ,{sw:True}         , {},                         )

        addop("xlat",  [0xD7],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("xor",   [0x82],             d6,    [imm]         , {w8:(0,0)}         ,{se:True}         , {},                         )
        addop("xor",   [0x34],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("xor",   [0x80],             d6,    [imm]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("xor",   [0x30],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("monitor",[0x0F, 0x01, 0xC8],noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("mwait", [0x0F, 0x01, 0xC9], noafs, no_rm         , {}                 ,{}                , {},                         )

        #x87 fpu                                                                                        , {}

        addop("fadd",  [0xD8],             d0,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fadd",  [0xD8, 0xC0],       reg,   [r_eax]       , {sw:(0,2)}         ,{sd:True,sw:False}, {},                         )
        addop("fiadd", [0xDE],             d0,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("faddp", [0xDE, 0xC0],       reg,   no_rm         , {}                 ,{sd:True,sw:True} , {},                         )

        addop("fbld",  [0xDF],             d4,    no_rm         , {}                 ,{}                , {},                         )
        addop("fbstp", [0xDF],             d6,    no_rm         , {}                 ,{}                , {},                         )

        #ddop("fclex", [0x9B, 0xDB, 0xE2], noafs, no_rm         , {}                 ,{}                , {},                         ) #XXX no mnemo
        addop("fnclex",[0xDB, 0xE2],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("ficom", [0xDE],             d2,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("ficomp",[0xDE],             d3,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )

        addop("fcom",  [0xD8],             d2,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fcom",  [0xD8, 0xD0],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fcomp", [0xD8],             d3,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fcomp", [0xD8, 0xD8],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fcompp",[0xDE, 0xD9],       noafs, no_rm         , {}                 ,{}                , {},                         )



        addop("fdiv",  [0xD8],             d6,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fdivr", [0xD8],             d7,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fdiv",  [0xDC, 0xF8],       reg,   [r_eax]       , {        }         ,{sd:True,sw:True }, {},                         )
        addop("fidiv", [0xDE],             d6,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fidivr",[0xDE],             d7,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fdivp", [0xDE, 0xF8],       reg,   no_rm         , {}                 ,{sd:True,sw:True} , {},                         )

        addop("fdiv",  [0xD8, 0xF0],       reg,   [r_eax]       , {        }         ,{sd:True,sw:False}, {},                         )
        addop("fdivr", [0xD8, 0xF8],       reg,   [r_eax]       , {        }         ,{sd:True,sw:False}, {},                         )
        addop("fdivr", [0xDC, 0xF0],       reg,   [r_eax]       , {        }         ,{sd:True,sw:True }, {},                         )
        addop("fdivrp",[0xDE, 0xF0],       reg,   no_rm         , {}                 ,{sd:True,sw:True},  {},                         )


        addop("wait",  [0x9B],             noafs, no_rm         , {}                 ,{}                , {},                         )
        #ddop("fwait", [0x9B],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fild",  [0xDF],             d0,    no_rm         , {wd:(0,2)}         ,{}        , {},                         )
        addop("fild",  [0xDF],             d5,    no_rm         , {}                 ,{sd:False,wd:False}, {},                         ) #XXX 64


        addop("finit", [0x9B, 0xDB, 0xE3], noafs, no_rm         , {}                 ,{}                , {},                         ) #XXX no mnemo
        addop("fninit",[0xDB, 0xE3],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fist",  [0xDF],             d2,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fistp", [0xDF],             d3,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fistp", [0xDF],             d7,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 64
        addop("fisttp",[0xDF],             d1,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fisttp",[0xDD],             d1,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 64



        addop("fmul",  [0xD8],             d1,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fmul",  [0xD8, 0xC8],       reg,   [r_eax]       , {sw:(0,2)}         ,{sd:True,sw:False}, {},                         )
        addop("fimul", [0xDE],             d1,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fmulp", [0xDE, 0xC8],       reg,   no_rm         , {}                 ,{sd:True,sw:True} , {},                         )


        addop("fcmovb",[0xDA, 0xC0],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fcmove",[0xDA, 0xC8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fcmovbe",[0xDA, 0xD0],      reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fcmovu",[0xDA, 0xD8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fcmovnb",[0xDB, 0xC0],      reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fcmovne",[0xDB, 0xC8],      reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fcmovnbe",[0xDB, 0xD0],     reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fcmovnu",[0xDB, 0xD8],      reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        addop("frstor",[0xDD],             d4,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX 94/108

        #ddop("fsave", [0x9B, 0xDD],       d6,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnsave",[0xDD],             d6,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX 94/108


        addop("fst",   [0xD9],             d2,    [rmr]         , {sd:(0,2)}         ,{sd:True}         , {},                         )
        addop("fst",   [0xDD, 0xD0],       reg,   no_rm         , {}                 ,{sd:True}        , {},                         )
        addop("fstp",  [0xD9],             d3,    [rmr]         , {sd:(0,2)}         ,{sd:True}         , {},                         )
        addop("fstp",  [0xDB],             d7,    no_rm         , {}                 ,{sd:'fp80'}       , {},                         ) #XXX 80
        addop("fstp",  [0xDD, 0xD8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        #ddop("fstcw", [0x9B, 0xD9],       d7,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnstcw",[0xD9],             d7,    no_rm         , {}                 ,{wd:True}         , {},                         )
        #ddop("fstenv",[0x9B, 0xD9],       d6,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnstenv",[0xD9],            d6,    no_rm         , {}                 ,{wd:False}        , {},                         )

        addop("f2xm1", [0xD9, 0xF0],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fnop",  [0xD9, 0xD0],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fpatan",[0xD9, 0xF3],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fprem", [0xD9, 0xF8],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fprem1",[0xD9, 0xF5],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fptan", [0xD9, 0xF2],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("frndint",[0xD9, 0xFC],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fscale",[0xD9, 0xFD],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fsin",  [0xD9, 0xFE],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fsincos",[0xD9, 0xFB],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fsqrt", [0xD9, 0xFA],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fcos",  [0xD9, 0xFF],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fdecstp",[0xD9, 0xF6],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fincstp",[0xD9, 0xF7],      noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fld",   [0xD9],             d0,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fld",   [0xDB],             d5,    no_rm         , {}                 ,{sd:'fp80'}       , {},                         ) #XXX 80
        addop("fld",   [0xD9, 0xC0],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        addop("fcomi", [0xDB, 0xF0],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fcomip",[0xDF, 0xF0],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fucomi",[0xDB, 0xE8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fucomip",[0xDF, 0xE8],      reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        addop("fldcw", [0xD9],             d5,    no_rm         , {}                 ,{wd:True}         , {},                         )
        addop("fldenv",[0xD9],             d4,    no_rm         , {}                 ,{wd:False}        , {},                         )
        addop("fchs",  [0xD9, 0xE0],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("fabs",  [0xD9, 0xE1],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fld1",  [0xD9, 0xE8],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldl2t",[0xD9, 0xE9],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldl2e",[0xD9, 0xEA],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldpi", [0xD9, 0xEB],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldlg2",[0xD9, 0xEC],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldln2",[0xD9, 0xED],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldz",  [0xD9, 0xEE],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )


        #ddop("fstsw", [0x9B, 0xDD],       d7,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnstsw",[0xDD],             d7,    no_rm         , {}                 ,{wd:True}         , {},                         )
        #ddop("fstsw",[0x9B, 0xDF, 0xE0],  noafs, no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnstsw",[0xDF, 0xE0],       noafs, no_rm         , {}                 ,{wd:False}        , {},                         )

        addop("ffree", [0xDD, 0xC0],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("ffreep",[0xDF, 0xC0],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        addop("fsub",  [0xD8],             d4,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fsubr", [0xD8],             d5,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fsub",  [0xDC, 0xE8],       reg,   [r_eax]       , {        }         ,{sd:True,sw:True }, {},                         )
        addop("fisub", [0xDE],             d4,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fisubr",[0xDE],             d5,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fsubp", [0xDE, 0xE8],       reg,   no_rm         , {}                 ,{sd:True,sw:True} , {},                         )

        addop("fsub",  [0xD8, 0xE0],       reg,   [r_eax]       , {        }         ,{sd:True,sw:False}, {},                         )
        addop("fsubr", [0xD8, 0xE8],       reg,   [r_eax]       , {        }         ,{sd:True,sw:False}, {},                         )
        addop("fsubr", [0xDC, 0xE0],       reg,   [r_eax]       , {        }         ,{sd:True,sw:True }, {},                         )
        addop("fsubrp",[0xDE, 0xE0],       reg,   no_rm         , {}                 ,{sd:True,sw:True} , {},                         )

        addop("ftst",  [0xD9, 0xE4],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fucom", [0xDD, 0xE0],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fucomp",[0xDD, 0xE8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fucompp",[0xDA, 0xE9],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fxam",  [0xD9, 0xE5],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fxch",  [0xD9, 0xC8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        addop("clflush", [0x0F, 0xAE],     d7,    no_rm         , {}                 ,{}                , {},                         )
        addop("xsaveopt",[0x0F, 0xAE],     d6,    no_rm         , {}                 ,{}                , {},                         )
        addop("xrstor",  [0x0F, 0xAE],     d5,    no_rm         , {}                 ,{}                , {},                         )
        addop("xsave",   [0x0F, 0xAE],     d4,    no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fxrstor", [0x0F, 0xAE],     d1,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 512
        addop("fxsave",  [0x0F, 0xAE],     d0,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 512
        addop("fxtract", [0xD9, 0xF4],     noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fyl2x",   [0xD9, 0xF1],     noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fyl2xp1", [0xD9, 0xF9],     noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        # NB: F2 0F 10 ... is "movsd", same mnemonic as the "move string" movsd
        addop("mov#ups#",   [0x0F, 0x10],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("mov#ups#",   [0x0F, 0x11],  noafs, [rmr]         , {}                 ,{mmx:True}        , {sw:True},                  )
        addop("mov#lps#",   [0x0F, 0x12],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("mov#lps#",   [0x0F, 0x13],  noafs, [rmr]         , {}                 ,{mmx:True}        , {sw:True},                  )
        addop("unpckl#ps#", [0x0F, 0x14],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("unpckh#ps#", [0x0F, 0x15],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("mov#hps#",   [0x0F, 0x16],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("mov#hps#",   [0x0F, 0x17],  noafs, [rmr]         , {}                 ,{mmx:True}        , {sw:True},                  )

        addop("mova#ps#",   [0x0F, 0x28],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("mova#ps#",   [0x0F, 0x29],  noafs, [rmr]         , {}                 ,{mmx:True}        , {sw:True},                  )
        addop("cvt#pi2ps",  [0x0F, 0x2A],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("movnt#ps#",  [0x0F, 0x2B],  noafs, [rmr]         , {}                 ,{mmx:True}        , {sw:True},                  )
        addop("cvtt#ps2pi", [0x0F, 0x2C],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("cvt#ps2pi",  [0x0F, 0x2D],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("ucomis#s#",  [0x0F, 0x2E],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("comis#s#",   [0x0F, 0x2F],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#shufb",   [0x0F, 0x38,0x00], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#haddw",   [0x0F, 0x38,0x01], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#haddd",   [0x0F, 0x38,0x02], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#haddsw",  [0x0F, 0x38,0x03], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#maddubsw",[0x0F, 0x38,0x04], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#hsubw",   [0x0F, 0x38,0x05], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#hsubd",   [0x0F, 0x38,0x06], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#hsubsw",  [0x0F, 0x38,0x07], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#signb",   [0x0F, 0x38,0x08], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#signw",   [0x0F, 0x38,0x09], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#signd",   [0x0F, 0x38,0x0A], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#mulhrsw", [0x0F, 0x38,0x0B], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#blendvb", [0x0F, 0x38,0x10], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("blendv##PS#",[0x0F, 0x38,0x14], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("blendv##PD#",[0x0F, 0x38,0x15], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#test",    [0x0F, 0x38,0x17], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#absb",    [0x0F, 0x38,0x1C], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#absw",    [0x0F, 0x38,0x1D], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#absd",    [0x0F, 0x38,0x1E], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#muldq",   [0x0F, 0x38,0x28], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#cmpeqq",  [0x0F, 0x38,0x29], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#ackusdw", [0x0F, 0x38,0x2b], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#cmpgtq",  [0x0F, 0x38,0x37], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#minsb",   [0x0F, 0x38,0x38], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#minsd",   [0x0F, 0x38,0x39], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#minuw",   [0x0F, 0x38,0x3A], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#minud",   [0x0F, 0x38,0x3B], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#maxsb",   [0x0F, 0x38,0x3C], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#maxsd",   [0x0F, 0x38,0x3D], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#maxuw",   [0x0F, 0x38,0x3E], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#maxud",   [0x0F, 0x38,0x3F], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#mulld",   [0x0F, 0x38,0x40], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#hminposuw",[0x0F,0x38,0x41], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movsxbw", [0x0F, 0x38,0x20], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movsxbd", [0x0F, 0x38,0x21], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movsxbq", [0x0F, 0x38,0x22], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movsxwd", [0x0F, 0x38,0x23], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movsxwq", [0x0F, 0x38,0x24], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movsxdq", [0x0F, 0x38,0x25], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movzxbw", [0x0F, 0x38,0x30], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movzxbd", [0x0F, 0x38,0x31], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movzxbq", [0x0F, 0x38,0x32], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movzxwd", [0x0F, 0x38,0x33], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movzxwq", [0x0F, 0x38,0x34], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("#p#movzxdq", [0x0F, 0x38,0x35], noafs, [rmr]     , {}                 ,{mmx:True}        , {},                         )
        addop("round##PS#", [0x0F, 0x3A,0x08], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("round##PD#", [0x0F, 0x3A,0x09], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("round##SS#", [0x0F, 0x3A,0x0A], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("round##SD#", [0x0F, 0x3A,0x0B], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("blend##PS#", [0x0F, 0x3A,0x0C], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("blend##PD#", [0x0F, 0x3A,0x0D], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("#p#blendw",  [0x0F, 0x3A,0x0E], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("#p#alignr",  [0x0F, 0x3A,0x0F], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("#p#extrb",   [0x0F, 0x3A,0x14], noafs, [rmr,u08] , {}                 ,{mmx:True,sw:True}, {w8:True},                  )
        addop("#p#extrw",   [0x0F, 0x3A,0x15], noafs, [rmr,u08] , {}                 ,{mmx:True,sw:True}, {w8:True},                  )
        addop("#p#extrd",   [0x0F, 0x3A,0x16], noafs, [rmr,u08] , {}                 ,{mmx:True,sw:True}, {w8:True},                  )
        addop("extract##PS#",[0x0F,0x3A,0x17], noafs, [rmr,u08] , {}                 ,{mmx:True,sw:True}, {w8:True},                  )
        addop("#p#insrb",   [0x0F, 0x3A,0x20], noafs, [rmr,u08] , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#insrd",   [0x0F, 0x3A,0x22], noafs, [rmr,u08] , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("dp##PS#",    [0x0F, 0x3A,0x40], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("dp##PD#",    [0x0F, 0x3A,0x41], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("m##PS#adbw", [0x0F, 0x3A,0x42], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("#p#clmumqdq",[0x0F, 0x3A,0x44], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("#p#cmpestrm",[0x0F, 0x3A,0x60], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("#p#cmpestri",[0x0F, 0x3A,0x61], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("#p#cmpistrm",[0x0F, 0x3A,0x62], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("#p#cmpistri",[0x0F, 0x3A,0x63], noafs, [rmr,u08] , {}                 ,{mmx:True}, {w8:True},                  )
        addop("movmskp#S#", [0x0F, 0x50],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )

        addop("sqrt#ps#",   [0x0F, 0x51],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("rsqrt#ps#",  [0x0F, 0x52],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("rcp#ps#",    [0x0F, 0x53],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("and#ps#",    [0x0F, 0x54],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("andn#ps#",   [0x0F, 0x55],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("or#ps#",     [0x0F, 0x56],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("xor#ps#",    [0x0F, 0x57],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("add#ps#",    [0x0F, 0x58],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("mul#ps#",    [0x0F, 0x59],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("cvt#ps2pd",  [0x0F, 0x5A],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("cvt#dq2ps",  [0x0F, 0x5B],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("sub#ps#",    [0x0F, 0x5C],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("min#ps#",    [0x0F, 0x5D],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("div#ps#",    [0x0F, 0x5E],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("max#ps#",    [0x0F, 0x5F],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )

        addop("#p#unpcklbw",[0x0F, 0x60],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#unpcklwd",[0x0F, 0x61],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#unpckldq",[0x0F, 0x62],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#acksswb", [0x0F, 0x63],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#cmpgtb",  [0x0F, 0x64],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#cmpgtw",  [0x0F, 0x65],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#cmpgtd",  [0x0F, 0x66],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#ackuswb", [0x0F, 0x67],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#unpckhbw",[0x0F, 0x68],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#unpckhwd",[0x0F, 0x69],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#unpckhdq",[0x0F, 0x6A],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#ackssdw", [0x0F, 0x6B],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#unpcklqdq",[0x0F,0x6C],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#unpckhqdq",[0x0F,0x6D],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )

        addop("mov#d#",     [0x0F, 0x6e],  noafs, [rmr]         , {sw:(1,4)}         ,{mmx:True}        , {sw:False},                 )
        addop("mov#qa#",    [0x0F, 0x6f],  noafs, [rmr]         , {sw:(1,4)}         ,{mmx:True}        , {sw:False},                 )
        addop("pshuf#w#",   [0x0F, 0x70],  noafs, [rmr,u08]     , {}                 ,{mmx:True}        , {w8:True},                  )

        addop("#p#srlw",    [0x0F, 0x71],  d2,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#sraw",    [0x0F, 0x71],  d4,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#sllw",    [0x0F, 0x71],  d6,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#srld",    [0x0F, 0x72],  d2,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#srad",    [0x0F, 0x72],  d4,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#slld",    [0x0F, 0x72],  d6,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#srlq",    [0x0F, 0x73],  d2,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#srldq",   [0x0F, 0x73],  d3,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#sllq",    [0x0F, 0x73],  d6,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#slldq",   [0x0F, 0x73],  d7,    [u08]         , {}                 ,{mmx:True}        , {w8:True},                  )

        addop("#p#cmpeqb",  [0x0F, 0x74],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#cmpeqw",  [0x0F, 0x75],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#cmpeqd",  [0x0F, 0x76],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("hadd#pd#",   [0x0F, 0x7C],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )

        # "xadd" covers     [0x0F, 0xC0] [0x0F, 0xC1]
        addop("cmp#ps#",    [0x0F, 0xC2],  noafs, [rmr,u08]     , {}                 ,{mmx:True}        , {w8:True},                  )
        # "movnti" covers   [0x0F, 0xC3]
        addop("#p#insrw",   [0x0F, 0xC4],  noafs, [rmr,u08]     , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("#p#extrw",   [0x0F, 0xC5],  noafs, [rmr,u08]     , {}                 ,{mmx:True}        , {w8:True},                  )
        addop("shuf#ps#",   [0x0F, 0xC6],  noafs, [rmr,u08]     , {}                 ,{mmx:True}        , {w8:True},                  )
        # "cmpxchg8b", "rdrand" for   [0x0F, 0xC7]
        # "bswap" covers    [0x0F, 0xC8] ... [0x0F, 0xCF]

        addop("addsub#pd#", [0x0F, 0xD0],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#srlw",    [0x0F, 0xD1],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#srld",    [0x0F, 0xD2],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#srlq",    [0x0F, 0xD3],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#addq",    [0x0F, 0xD4],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#mullw",   [0x0F, 0xD5],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("movq",       [0x0F, 0xD6],  noafs, [rmr]         , {}                 ,{mmx:True}        , {sw:True},                  )
        addop("pmovmskb",   [0x0F, 0xD7],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#subusb",  [0x0F, 0xD8],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#subusw",  [0x0F, 0xD9],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#minub",   [0x0F, 0xDA],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#and",     [0x0F, 0xDB],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#addusb",  [0x0F, 0xDC],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#addusw",  [0x0F, 0xDD],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#maxub",   [0x0F, 0xDE],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#andn",    [0x0F, 0xDF],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#avgb",    [0x0F, 0xE0],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#sraw",    [0x0F, 0xE1],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#srad",    [0x0F, 0xE2],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#avgw",    [0x0F, 0xE3],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#mulhuw",  [0x0F, 0xE4],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#mulhw",   [0x0F, 0xE5],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("cvt#pd2dq",  [0x0F, 0xE6],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("movnt#q#",   [0x0F, 0xE7],  noafs, [rmr]         , {}                 ,{mmx:True}        , {sw:True},                  )
        addop("#p#subsb",   [0x0F, 0xE8],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#subsw",   [0x0F, 0xE9],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#minsw",   [0x0F, 0xEA],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#or",      [0x0F, 0xEB],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#addsb",   [0x0F, 0xEC],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#addsw",   [0x0F, 0xED],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#maxsw",   [0x0F, 0xEE],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#xor",     [0x0F, 0xEF],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#sllw",    [0x0F, 0xF1],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#slld",    [0x0F, 0xF2],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#sllq",    [0x0F, 0xF3],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#muludq",  [0x0F, 0xF4],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#maddwd",  [0x0F, 0xF5],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#sadbw",   [0x0F, 0xF6],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("maskmov#qu#",[0x0F, 0xF7],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#subb",    [0x0F, 0xF8],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#subw",    [0x0F, 0xF9],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#subd",    [0x0F, 0xFA],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#subq",    [0x0F, 0xFB],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#addb",    [0x0F, 0xFC],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#addw",    [0x0F, 0xFD],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )
        addop("#p#addd",    [0x0F, 0xFE],  noafs, [rmr]         , {}                 ,{mmx:True}        , {},                         )

        pm = self.db_mnemo[0x9c]
        self.pushfw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.pushfw_m.name = "pushfw"

        self.popfw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.popfw_m.name = "popfw"

        pm = self.find_mnemo("lodsd")[0]
        self.lodsw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.lodsw_m.name = "lodsw"

        pm = self.find_mnemo("stosd")[0]
        self.stosw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.stosw_m.name = "stosw"

        pm = self.find_mnemo("movsd")[0]
        self.movsw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.movsw_m.name = "movsw"

        pm = self.find_mnemo("cmpsd")[0]
        self.cmpsw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.cmpsw_m.name = "cmpsw"

        pm = self.find_mnemo("scasd")[0]
        self.scasw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.scasw_m.name = "scasw"

        pm = self.find_mnemo("xrstor")[0]
        self.lfence_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)
        self.lfence_m.name = "lfence"

        pm = self.find_mnemo("xsaveopt")[0]
        self.mfence_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)
        self.mfence_m.name = "mfence"

        pm = self.find_mnemo("clflush")[0]
        self.sfence_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)
        self.sfence_m.name = "sfence"

x86mndb = x86allmncs()

mmx_prefixes = [0x00, 0x66, 0xF2, 0xF3]
mmx_suffixes = {
    '#w#':    ('w', 'd', 'lw', 'hw'),
    '#d#':    ('d', 'd', 'INVALID', 'q'),
    '#q#':    ('q', 'dq', 'INVALID', 'INVALID'),
    '#qa#':   ('q', 'dqa', 'INVALID', 'dqu'),
    '#qu#':   ('q', 'dqu', 'INVALID', 'INVALID'),
    '#p#':    ('p', 'p', 'INVALID', 'INVALID'),
    '#s#':    ('s', 'd', 'INVALID', 'INVALID'),
    '#S#':    ('s', 'd', 'REPZ', 'REPNZ'),
    '#ps#':   ('ps', 'pd', 'sd', 'ss'),
    '#pd#':   ('INVALID', 'pd', 'ps', 'INVALID'),
    '#hps#':  ('hps', 'hpd', 'INVALID', 'shdup'),
    '#lps#':  ('lps', 'lpd', 'ddup', 'sldup'),
    '#ups#':  ('ups', 'upd', 'sd', 'ss'),
    '#ps2pd': ('ps2pd', 'pd2ps', 'sd2ss', 'ss2sd'),
    '#ps2pi': ('ps2pi', 'pd2pi', 'sd2si', 'ss2si'),
    '#pi2ps': ('pi2ps', 'pi2pd', 'si2sd', 'si2ss'),
    '#dq2ps': ('dq2ps', 'ps2dq', 'INVALID', 'tps2dq'),
    '#pd2dq': ('INVALID', 'tpd2dq', 'pd2dq', 'dq2pd'),
    '##PS#':   ('INVALID', 'ps', 'INVALID', 'INVALID'),
    '##PD#':   ('INVALID', 'pd', 'INVALID', 'INVALID'),
    '##SS#':   ('INVALID', 'ss', 'INVALID', 'INVALID'),
    '##SD#':   ('INVALID', 'sd', 'INVALID', 'INVALID'),
}
def mmx_set_suffix(name, p):
    for suffix in mmx_suffixes:
        if suffix in name:
            import re
            r = re.match(r'(\S*)'+suffix+r'(\S*)', name)
            r = r.groups()
            suffix = mmx_suffixes[suffix][p]
            return r[0] + suffix + r[1]
    return name

mnemo_mmx_hash = {}
for m in x86mndb.mnemo_lookup:
    if '#' in m:
        for p in range(4):
            name = mmx_set_suffix(m, p)
            if 'INVALID' in name: continue
            mnemo_mmx_hash[name] = m
    if m == "cmp#ps#":
        for p in mnemo_sse_cmp:
            mnemo_mmx_hash[p] = m
mnemo_mmx = [ 'pmovmskb', 'cvttpd2dq', 'movhlps', 'movlhps' ] + list(mnemo_mmx_hash.keys())

mnemo_float_optional_suffix = ['fld','fst','fstp'] + float_arith + float_arith_p
att_mnemo_table = {
    'suffix_none': [
        'leave', 'ret', 'nop',
        'fldl2e', 'fldl2t', 'fldpi', 'fldlg2', 'fldln2', 'fyl2x', 'fyl2xp1',
        'fcos', 'fsin', 'fsincos', 'fscale',
        'f2xm1', 'fincstp', 'fdecstp', 'finit', 'fninit',
        'fld1', 'fldz', 'fucom', 'fucomi', 'fucomip', 'fucomp', 'fucompp',
        'fnop', 'fchs', 'fxch', 'fabs', 'fsqrt', 'frndint', 'fxam',
        'fldcw', 'fnstcw', 'fnstsw', 'fprem', 'fprem1', 'fpatan', 'fptan',
        'ffree', 'ffreep', 'fcompp',
        'sahf', 'bswap',
        'movsb', 'cmpsb', 'stosb', 'lodsb', 'scasb',
        'movsw', 'cmpsw', 'stosw', 'lodsw', 'scasw',
        'aaa', 'aad', 'aam', 'aas', 'daa', 'das', 'clc', 'cld', 'cli', 'cmc',
        'stc', 'std', 'sti',
        'cpuid', 'in', 'out', 'ud2', 'wait',
        'int', 'fnclex', 'cmpxchg', 'lahf',
        'fxsave',
        'fxrstor',
        'ldmxcsr',
        'stmxcsr',
        'xsave',
        'xrstor',
        'xsaveopt',
        'clflush',
        'lfence',
        'mfence',
        'sfence',
        'bound',
        ] + mnemo_mmx + mnemo_prefetch + mnemo_float_optional_suffix,
    'suffix_one_ptr': [ {
            'b': x86_afs.u08,
            'w': x86_afs.u16,
            'l': x86_afs.u32, },
        'lea', 'mov', 'xchg', 'push', 'pop',
        'test', 'cmp', 'and', 'xor', 'or', 'not', 'neg',
        'add', 'adc', 'sub', 'mul', 'div', 'imul', 'idiv', 'inc', 'dec', 'xadd',
        'sal', 'sar', 'shl', 'shr', 'rol', 'ror', 'sbb', 'shld', 'shrd', 'bsf', 'bsr',
        'bt', 'bts', 'btr', 'btc', 'lgdt',
        'cvtsi2sd', 'cvtsi2ss', 'fisttp',
        'cmpxchg', 'movnti', 'rdrand',
        ],
    'suffix_one_iflt': [ {
            's': x86_afs.u16,
            'l': x86_afs.u32,
            'q': x86_afs.f64, },
        'fiadd', 'fisub', 'fisubr', 'fimul', 'fidiv', 'fidivr', 'ficom', 'ficomp', 'fild', 'fist', 'fistp', 'fisttp',
        ],
    'suffix_one_flt': [ {
            's': x86_afs.f32,
            'l': x86_afs.f64,
            't': x86_afs.f80, },
        ] + mnemo_float_optional_suffix,
    'correspondance' : {
        'movsl': 'movsd',
        'cmpsl': 'cmpsd',
        'stosl': 'stosd',
        'lodsl': 'lodsd',
        'scasl': 'scasd',
        'pushf': 'pushfd',
        'pushfl':'pushfd',
        'popf':  'popfd',
        'popfl': 'popfd',
        'ljmp':  'jmpf',
        # sign extend
        'cbtw': 'cbw',
        'cwtl': 'cwde',
        'cwtd': 'cwd',
        'cltd': 'cdq',
        'cltq': 'cdqe', # x86-64 only
        'cqto': 'cqo',  # x86-64 only
        },
}

def mnemo_from_att_set_size(size, args):
    for a in args:
        if a[x86_afs.ad]:
            a[x86_afs.ad] = size
            a[x86_afs.size] = size

def att_bug_fsub_fdiv(name, args, asm_format):
    # https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=372528
    if name[-1] == 'p':
        if name[4:] == 'p':  return name[:4]+'rp'
        if name[4:] == 'rp': return name[:4]+'p'
        NEVER
    elif len(args) == 2 and not 0 in args[0]:
        if name[4:] == '':   return name+'r'
        if name[4:] == 'r':  return name[:4]
        NEVER
    else:
        return name

def mnemo_from_att(prefix, name, args, asm_format):
    if name in ['call', 'jmp']:
        for a in args:
            if a[x86_afs.ad] == True:
                a[x86_afs.ad] = False
        return prefix, name
    elif name in ['calll', 'jmpl', 'retl', 'bswapl']:
        # clang on MacOS X
        if name == 'calll':
            for a in args:
                if a[x86_afs.ad] == True:
                    a[x86_afs.ad] = False
        return prefix, name[:-1]
    elif name == 'fucompi':
        # clang on MacOS X
        return prefix, 'fucomip'
    elif name == 'fwait':
        # both mnenomics are valid
        return prefix, 'wait'
    elif name.startswith('j'): # Conditional jumps
        for a in args:
            if a[x86_afs.ad]:
                a[x86_afs.ad] = False
        return prefix, name
    elif name.startswith('set'):
        if name.endswith('b') and not name in [ 'setb', 'setnb' ]:
            name = name[:-1]
        mnemo_from_att_set_size(x86_afs.u08, args)
        return prefix, name
    elif name.startswith('cmov'):
        if name.endswith('w'):
            name = name[:-1]
            mnemo_from_att_set_size(x86_afs.u16, args)
        elif len(name) > 5 and name.endswith('l'):
            # Don't transform cmovl to cmov
            name = name[:-1]
            mnemo_from_att_set_size(x86_afs.u32, args)
        else:
            mnemo_from_att_set_size(x86_afs.u32, args)
        return prefix, name
    elif name.startswith('fcmov'):
        return prefix, name
    elif name in att_mnemo_table['correspondance']:
        return prefix, att_mnemo_table['correspondance'][name]
    elif name in att_mnemo_table['suffix_none']:
        if name[:4] in ['fsub', 'fdiv']:
            return prefix, att_bug_fsub_fdiv(name, args, asm_format)
        elif name in ['fldcw', 'fnstcw']:
            mnemo_from_att_set_size(x86_afs.u16, args)
        return prefix, name
    # Suffix that indicates operands sizes
    for table in [
        'suffix_one_flt',
        'suffix_one_iflt',
        'suffix_one_ptr',
        ]:
        if name.startswith('test') or name.startswith('xchg'):
            # Be liberal in what we accept, because old clang has bugs
            if args[1][x86_afs.ad] != False: args.reverse()
        if name[:-1] in att_mnemo_table[table]:
            size = att_mnemo_table[table][0][name[-1]]
            mnemo_from_att_set_size(size, args)
            if name[:-1] == 'push' and is_imm(args[0]) and size == x86_afs.u16:
                args[0][x86_afs.size] = size
            return prefix, name[:-1]
    if name[-2:] == 'll' and name[:-2] in att_mnemo_table['suffix_one_iflt']:
        mnemo_from_att_set_size(x86_afs.f64, args)
        return prefix, name[:-2]
    # TODO: 'suffix_one_ptr' without suffix => detection of size from register
    elif name.startswith('movs') or name.startswith('movz'):
        size = att_mnemo_table['suffix_one_ptr'][0][name[-2]]
        mnemo_from_att_set_size(size, args)
        return prefix, name[:4]+'x'
    elif name == 'push':
        return prefix, 'push'
    raise ValueError("Mnemonic %r unknown"%name)

def mnemo_to_att(name, args, asm_format):
    if name == 'movsd' and args[0][x86_afs.size] != 'xmm' \
                       and args[1][x86_afs.size] != 'xmm':
        # Special case: string instruction
        return 'movsl'
    if name in mnemo_float_optional_suffix and not args[0][x86_afs.ad]:
        if name[:4] in ['fsub', 'fdiv']:
            return att_bug_fsub_fdiv(name, args, asm_format)
        return name
    for table in [
        'suffix_one_ptr',
        'suffix_one_iflt',
        'suffix_one_flt',
        ]:
        if name in att_mnemo_table[table]:
            if asm_format.endswith('objdump'):
                # If no imm argument and not ptr, then the size of args is implicit
                has_imm = [ is_imm(a) for a in args ]
                if not True in has_imm:
                    return name
                has_add = [ is_address(a) for a in args ]
                if not True in has_add:
                    return name
            for suffix, size in att_mnemo_table[table][0].items():
                if x86_afs.size in args[0]:
                    argsize = args[0][x86_afs.size]
                elif x86_afs.imm in args[0]:
                    argsize = 'u%02d'%tab_int_size[type(args[0][x86_afs.imm])]
                if size == argsize:
                    return name + suffix
    if name == 'call' or name.startswith('j'):
        return name
    elif name.startswith('set'):
        return name
    elif name.startswith('cmov'):
        return name
    elif name.startswith('fcmov'):
        return name
    elif name in att_mnemo_table['suffix_none']:
        return name
    elif name in att_mnemo_table['correspondance'].values():
        return sorted([key 
            for key, value in att_mnemo_table['correspondance'].items()
            if name == value ])[0]
    elif name == 'movsx' or name == 'movzx':
        sz = (args[0][x86_afs.size], args[1][x86_afs.size])
        if   sz == (u32, u08):
            return name[:4]+'bl'
        elif sz == (u32, u16):
            return name[:4]+'wl'
        elif sz == (u16, u08):
            return name[:4]+'bw'
    elif name == 'push':
        return 'pushl'
    raise ValueError("Mnemonic %r unknown"%name)


class x86_mnemo_metaclass(type):
    rebuilt_inst = True

    def __new__(cls, name, bases, dctn):
        dctn['__slots__'] = ('opmode', 'admode', 'mnemo_mode', 'cmt',
            'prefix', 'm', 'arg', 'offset', 'l', 'b', 'txt',
            'arg_expr')
        return type.__new__(cls, name, bases, dctn)

    def dis(cls, op, attrib = {}):
        i = cls.__new__(cls)
        i.__init__(attrib)
        u = i._dis(op)
        if not u:
            return None
        return i
    def asm(cls, l, symbol_off = []):
        i = cls.__new__(cls)
        i.__init__() # admode = u32, opmode = u32, sex = 0)
        return i._asm(l, symbol_off)


    def fix_symbol(cls, a, symbol_pool = None):
        if type(a) in [int]+list(tab_int_size.keys()):
            return a

        cp = dict(a)
        if not x86_afs.symb in cp:
            return cp

        if not symbol_pool:
            del cp[x86_afs.symb]
            if not x86_afs.imm in cp:
                cp[x86_afs.imm] = 0
            return cp

        imm_total = 0
        if x86_afs.imm in cp:
            imm_total+=cp[x86_afs.imm]
        for s in cp[x86_afs.symb]:
            base_ad = symbol_pool.s['base_address'].offset_g
            imm_total+=cp[x86_afs.symb][s]*(s.offset_g+base_ad)

        cp[x86_afs.imm] = imm_total
        del cp[x86_afs.symb]


        return cp

    def is_mem(cls, a):
        return x86_afs.ad in a and a[x86_afs.ad]

    def get_label(cls, a):
        if not x86_afs.symb in a:
            return None
        n = a[x86_afs.symb]
        if len(n)!=1:
            return None
        k = list(n.keys())[0]
        if n[k] != 1:
            return None
        return k

x86_mn_base = x86_mnemo_metaclass('x86_mn_base', (object,), {})
class x86_mn(x86_mn_base):
    def __init__(self, attrib = {}):
        self.opmode = attrib.get('opmode', u32)
        self.admode = attrib.get('opmode', u32)
        self.mnemo_mode = self.opmode
        self.cmt = ""


    def get_attrib(self):
        return {"opmode":self.opmode,
                "admode":self.admode}

    def prefix2hex(self, prefix):
        return ""
    prefix2hex = classmethod(prefix2hex)


    def breakflow(self):
        return self.m.modifs[bkf]
    def splitflow(self):
        return self.m.modifs[spf]
    def dstflow(self):
        return self.m.modifs[dtf]

    def getnextflow(self):
        return self.offset+self.l

    def getdstflow(self):
        if self.m.name == "jmpf":
            # HACK
            return [self.arg[0]]
        if len(self.arg) !=1:
            raise ValueError('should be 1 arg %s' % self)
        a = self.arg[0]
        if is_imm(a) and not x86_afs.symb in a:
            dst = (self.offset+self.l+a[x86_afs.imm])&tab_max_uint[self.opmode]
            out = [dst]
        else:
            out = [a]
        return out

    def setdstflow(self, dst):
        if len(self.arg) !=1:
            raise ValueError('should be 1 arg %s' % self)
        if len(dst)==0:
            return
        if len(dst)!=1:
            raise ValueError('should be 1 dst')
        l = dst[0]

        self.arg = [{x86_afs.symb:{l:1}}]

    def fixdst(self, lbls, my_offset, is_mem):
        if len(self.arg) !=1:
            raise ValueError('should be 1 arg %s' % self)
        a = self.arg[0]
        l = list(a[x86_afs.symb].keys())[0]
        offset = lbls[l.name]
        if is_mem:
            arg = {x86_afs.ad:is_mem, x86_afs.imm:offset}
        else:
            arg = {x86_afs.imm:offset-(my_offset)}

        self.arg = [arg]

    def is_subcall(self):
        return self.m.name == 'call'

    def __str__(self, asm_format='intel_syntax noprefix'):
        if asm_format is None: asm_format = 'intel_syntax noprefix'
        prefix = self.prefix[:]
        mnemo = [ self.m.name ]
        if self.m.modifs[mmx]:
            if len(prefix) == 0: p = 0
            else: p = prefix.pop()
            p = mmx_prefixes.index(p)
            mnemo[0] = mmx_set_suffix(self.m.name, p)
            if mnemo[0] == 'movlps' \
                    and self.arg[0][x86_afs.ad] == False \
                    and self.arg[1][x86_afs.ad] == False:
                mnemo[0] = 'movhlps'
            if mnemo[0] == 'movhps' \
                    and self.arg[0][x86_afs.ad] == False \
                    and self.arg[1][x86_afs.ad] == False:
                mnemo[0] = 'movlhps'
        for p in prefix:
            # Group 1: Lock and repreat prefixes
            if p == 0xF0:
                mnemo.insert(0, "lock")
            elif p == 0xF2 and self.m.name[:-1] in ["cmps", "scas"]:
                mnemo.insert(0, "repnz")
            elif p == 0xF3 and self.m.name[:-1] in ["cmps", "scas"]:
                mnemo.insert(0, "repz")
            elif p == 0xF3:
                mnemo.insert(0, "rep")
            # Group 2: Segment override prefixes / Branch hints
            elif p in [0x2E,0x36,0x3E,0x26,0x64,0x65]:
                pass
            # Group 3: Operand-size override
            elif p == 0x66:
                pass
            # Group 4: Address-size override
            elif p == 0x67:
                pass
            else:
                mnemo.insert(0, "[0x%02x]"%p)

        args = self.arg[:]
        # special case when the argument should be omitted
        if len(args) == 1 and self.m.name in rep_sto_lod_sca:
            args[0:2] = []
        # special case when both arguments should be omitted
        if len(args) == 2 and self.m.name in rep_mov_cmp and x86_afs.segm in args[0]:
            args[0:2] = []
        # Implicit 'ax' argument
        if len(args) == 0 and self.m.name in ["fnstsw"]:
            args[0:1] = [r_ax]
        # Pseudo-Ops
        elif mnemo[-1] in ['cmpps', 'cmppd', 'cmpsd', 'cmpss'] and len(args)==2:
            predicate = int(args[2][x86_afs.imm] & 7)
            mnemo[-1] = 'cmp' + mnemo_sse_cmp_predicate[predicate] + mnemo[-1][-2:]
            args = [ args[0], args[1] ]
        args = [ dict_to_ad(a,
                       self.m.modifs,
                       self.opmode,
                       self.admode,
                       asm_format=asm_format)
                   for a in args]
        # Implicit 'st' floating point register argument
        if asm_format.endswith('noprefix'): st = 'st'
        else: st = '%st'
        if len(self.arg) > 0 and not is_address(self.arg[0]) \
                and self.arg[0][x86_afs.size] in [x86_afs.f32,x86_afs.f64]:
            if self.m.name in float_st_mnemo:
                args = [ st, args[0] ]
            elif self.m.name in float_arith_p:
                args = [ args[0], st ]
            elif self.m.name in float_arith:
                if args[0] == st+'(0)':
                    args = [ st, args[1] ]
                elif args[1] == st+'(0)':
                    args = [ args[0], st ]
                else:
                    NOT_POSSIBLE
        if len(args) == 0 and self.m.name in float_st_st1:
            args = [ st+'(1)' ]
        # Special case: when gcc produces 'rep ret'
        # http://mikedimmick.blogspot.fr/2008/03/what-heck-does-ret-mean.html
        # it usually puts it on two separate lines, and old versions of
        # GNU as don't like a true 'rep ret'
        if mnemo == ['rep','ret']:
            mnemo = ['rep;','ret']
        if asm_format.startswith('att_syntax'):
            args.reverse()
            mnemo[-1] = mnemo_to_att(mnemo[-1], self.arg, asm_format)
            if mnemo[-1] == 'call' or mnemo[-1].startswith('j'):
                if   args[0][0] == '$':
                    args[0] = args[0][1:]
                else:
                    args[0] = '*'+args[0]
        else:
            # jmp/call to indirect address has additional brackets
            if self.m.name in ['jmp','call'] and self.arg[0].get(x86_afs.ad, False):
                args[0] = "[%s]"%args[0]
            # push word imm has a specific syntax
            if self.m.name == 'push' and is_imm(self.arg[0]) and self.arg[0][x86_afs.size] == x86_afs.u16:
                args[0] = "WORD PTR %s"%args[0]
        if asm_format.endswith('objdump'):
            mnemo[-1] = "%-6s" % mnemo[-1]
            o = ' '.join(mnemo)+' '+','.join(args)
            if o == 'nop    ': o = 'nop'
        else:
            mnemo[-1] = "%-9s" % mnemo[-1]
            o = ' '.join(mnemo)+' '+', '.join(args)
        if self.cmt:
            o = "%-50s%s"%(o, self.cmt)
        return o

    def intsize(self, im, ext = False):
        if ext:
            return [uint16, uint32][self.opmode == u32](im)
        if self.m.modifs[w8]:
            return uint8(im)
        if self.opmode == u32:
            return uint32(im)
        elif self.opmode == u16:
            return uint16(im)
        else:
            raise ValueError('unknown mnemo mode %s' % im)

    def _dis(self, bin):
        if not hasattr(bin, 'offset'):
            from miasmX.core.bin_stream import bin_stream
            bin = bin_stream(bin)
        init_offset = bin.offset

        try:
            #find mnemonic
            l = x86mndb.db_mnemo
            m = None
            read_prefix = []
            prefix_done =False
            while True:
                c = ord(bin.readbs())
                if not prefix_done and c in x86_afs.x86_prefix:
                    read_prefix.append(c)
                    continue
                else:
                    prefix_done = True
                if l[c] is None:
                    log.debug( "unknown mnemo")
                    break
                if isinstance(l[c] ,mnemonic):
                    m = l[c]
                    break
                if type(l[c]) == list:
                    l = l[c]

            if m is None:
                return None
            self.m = m

            log.debug(m)
            log.debug("prefix: %s", read_prefix)

            #self.mnemo_mode = self.admode
            if 0x66 in read_prefix:
                self.opmode = [u16,u32][self.opmode==u16]
                if m.name in [ "cwde", "cdq" ]:
                    m = x86mndb.db_mnemo[0x66][m.opc[0]]
                    read_prefix = [_ for _ in read_prefix if _ != 0x66]
                #self.opmode = [u16,u32][size_op == u16]
            if 0x67 in read_prefix:
                self.admode = [u16,u32][self.admode == u16]



            #parse mnemonic args
            mnemo_args = []
            swap_args = m.modifs[sw]

            afs, dibs = m.afs, m.rm
            #digit
            if afs in [d0, d1, d2, d3, d4, d5, d6, d7]:
                if m.modifs[mmx]:
                    if read_prefix == []:
                        self.admode = mm
                    elif read_prefix == [0x66]:
                        self.admode = xmm
                re, modr = x86mndb.get_afs(bin, c, self.admode)
                mnemo_args.append(modr)
                mnemo_args[-1][x86_afs.size] = self.opmode

                if m.modifs[sd] is not None:
                    if   m.modifs[sd] == True:
                        mnemo_args[-1][x86_afs.size] = x86_afs.f32
                    elif m.modifs[sd] == False:
                        mnemo_args[-1][x86_afs.size] = x86_afs.f64
                    elif m.modifs[sd] == 'fp80':
                        mnemo_args[-1][x86_afs.size] = x86_afs.f80
                    else:
                        NEVER

                if m.modifs[w8] and not m.modifs[mmx]:
                    mnemo_args[-1][x86_afs.size] = x86_afs.u08
                if m.modifs[wd]:
                    #XXX check (for fnst??)=
                    mnemo_args[-1][x86_afs.size] = x86_afs.u16
                if rmr in dibs and not x86_afs.imm in modr and modr[x86_afs.ad] == False:
                    log.info("No register should be encoded here")
                    return None
            #+reg
            elif afs == reg:
                mafs = dict(x86mndb.get_afs_re(c&(0xFF^mask_reg)))
                if m.modifs[w8]:
                    mafs[x86_afs.size] = x86_afs.u08
                else:
                    mafs[x86_afs.size] = self.opmode

                mnemo_args.append(mafs)
            #rm mod
            elif afs in [noafs, cond]:
                if rmr in m.rm:
                    reg_cat = 0
                    if m.modifs[dr]:
                        reg_cat+=0x8
                    if m.modifs[cr]:
                        reg_cat+=0x10
                    if m.modifs[sg]:
                        reg_cat+=0x20
                    if m.modifs[mmx]:
                        # 'mafs' <- opmode, generating reg_cat
                        # 'modr' <- admode
                        if '#S#' in m.name:
                            self.opmode = u32
                            self.admode = xmm
                        elif m.name in ['#p#extrb', '#p#extrd', '#p#extrw'] \
                               and swap_args:
                            # 0x0F 0x3A ...
                            self.opmode = xmm
                            self.admode = u32
                        elif m.name in ['#p#insrb', '#p#insrd', '#p#insrw', 'extract##PS#']:
                            if read_prefix == []:
                                self.opmode = mm
                            else:
                                self.opmode = xmm
                            self.admode = u32
                        elif m.name in ['pmovmskb', '#p#extrw']:
                            # pextrw is 0x0F 0xC5 ...
                            self.opmode = u32
                            if read_prefix == []:
                                self.admode = mm
                            else:
                                self.admode = xmm
                        elif '##' in m.name:
                            self.opmode = xmm
                            self.admode = xmm
                        elif '#ps2pi' in m.name:
                            if read_prefix == [] or read_prefix == [0x66]:
                                self.opmode = mm
                            elif read_prefix == [0xF2] or read_prefix == [0xF3]:
                                self.opmode = u32
                            self.admode = xmm
                        elif '#pi2ps' in m.name:
                            self.opmode = xmm
                            if read_prefix == [] or read_prefix == [0x66]:
                                self.admode = mm
                            elif read_prefix == [0xF2] or read_prefix == [0xF3]:
                                self.admode = u32
                        elif   '#p#' in m.name \
                            or '#w#' in m.name \
                            or '#qa#' in m.name \
                            or '#qu#' in m.name:
                            if read_prefix == []:
                                self.opmode = mm
                            else:
                                self.opmode = xmm
                            self.admode = self.opmode
                        elif   '#s#' in m.name \
                            or '#ps#' in m.name \
                            or '#pd#' in m.name \
                            or '#ups#' in m.name \
                            or '#lps#' in m.name \
                            or '#hps#' in m.name \
                            or '#ps2pd' in m.name \
                            or '#dq2ps' in m.name \
                            or '#pd2dq' in m.name:
                            self.opmode = xmm
                            self.admode = xmm
                        elif m.name == 'movq':
                            self.opmode = xmm
                            if read_prefix == [] or read_prefix == [0x66]:
                                self.admode = x86_afs.f64
                            elif read_prefix == [0xF2] or read_prefix == [0xF3]:
                                self.admode = xmm
                        elif '#q#' in m.name: # movntq/movntdq//
                            if read_prefix == []:
                                self.opmode = mm
                            elif read_prefix == [0x66]:
                                self.opmode = xmm
                            self.admode = xmm
                        elif '#d#' in m.name: # movd/movd//movq
                            if read_prefix == []:
                                self.opmode = mm
                                self.admode = u32
                            elif read_prefix == [0x66]:
                                self.opmode = xmm
                                self.admode = u32
                            elif read_prefix == [0xF3]:
                                self.opmode = xmm
                                self.admode = xmm
                                if not swap_args: raise ValueError('Invalid')
                                swap_args = False
                        else:
                            log.debug('Unknown MMX', m.name)
                            raise ValueError('Unknown MMX', m.name)
                        if self.opmode == xmm:   reg_cat = x86_afs.reg_xmm_base
                        elif self.opmode == mm:  reg_cat = x86_afs.reg_mm_base
                        elif self.opmode == u32: reg_cat = 0
                        else:
                            NEVER
                    c = ord(bin.readbs())
                    re, modr = x86mndb.get_afs(bin, c, self.admode)
                    mafs = dict(x86mndb.get_afs_re(re+reg_cat))
                    if m.modifs[w8]:
                        modr[x86_afs.size] = x86_afs.u08
                        mafs[x86_afs.size] = x86_afs.u08
                    else:
                        modr[x86_afs.size] = self.opmode
                        mafs[x86_afs.size] = self.opmode
                    if m.modifs[se] !=None and not (imm in dibs or ims in dibs):
                        modr[x86_afs.size] = [x86_afs.u08, x86_afs.u16][m.modifs[se]]
                    if m.modifs[wd]:
                        modr[x86_afs.size] = x86_afs.u16
                        mafs[x86_afs.size] = x86_afs.u16
                    if m.modifs[mmx]:
                        modr[x86_afs.size] = self.admode
                        mafs[x86_afs.size] = self.opmode
                    if m.modifs[sg]:
                        mafs[x86_afs.size] = x86_afs.size_seg
                    if modr[x86_afs.ad]:
                        # For ModRM, the size of memory may not be the same
                        # as the size of the register
                        if m.name == 'mov#d#':
                            if   read_prefix == [0x66]:
                                modr[x86_afs.size] = x86_afs.f32
                            elif read_prefix == [0xF2]:
                                NEVER
                            elif read_prefix == [0xF3]:
                                modr[x86_afs.size] = x86_afs.f64
                        elif '#ps#' in m.name or m.name == 'mov#ups#':
                            if read_prefix == [0xF2]:
                                modr[x86_afs.size] = x86_afs.f64
                            elif read_prefix == [0xF3]:
                                modr[x86_afs.size] = x86_afs.f32
                        elif '#s#' in m.name:
                            if read_prefix == []:
                                modr[x86_afs.size] = x86_afs.f32
                            elif read_prefix == [0x66]:
                                modr[x86_afs.size] = x86_afs.f64
                            elif read_prefix == [0xF2] or read_prefix == [0xF3]:
                                NEVER
                        elif '#ps2pi' in m.name or '#ps2pd' in m.name:
                            if read_prefix == [] or read_prefix == [0xF2]:
                                modr[x86_afs.size] = x86_afs.f64
                            elif read_prefix == [0xF3]:
                                modr[x86_afs.size] = x86_afs.f32
                        elif '#pi2ps' in m.name:
                            if read_prefix == [] or read_prefix == [0x66]:
                                modr[x86_afs.size] = x86_afs.f64
                            elif read_prefix == [0xF2] or read_prefix == [0xF3]:
                                modr[x86_afs.size] = x86_afs.f32
                        elif '#pd2dq' in m.name:
                            if read_prefix == [0xF3]:
                                modr[x86_afs.size] = x86_afs.f64
                        elif   '#lps#' in m.name or '#hps#' in m.name:
                            if read_prefix == [] or read_prefix == [0x66]:
                                modr[x86_afs.size] = x86_afs.f64
                    mnemo_args.append(mafs)
                    mnemo_args.append(modr)
                    if afs == cond and m.name.startswith('set'):
                        mnemo_args.pop(0)
            else:
                log.debug('bug in %s %d'%(name, afs))
                raise ValueError('bug in %s %d'%(name, afs))

            #swap args?
            if swap_args:
                mnemo_args.reverse()

            dib_out = []
            for dib in dibs:
                #unsigned
                log.debug("Dib %s; Modifs: %s", dib, m.modifs)
                if dib in [u08, s08, u16, s16, u32, s32]:
                    if self.admode !=u32:
                        if dib == u32: dib = u16
                        if dib == s32: dib = s16
                    l = struct.calcsize(x86_afs.dict_size[dib])
                    d = struct.unpack(x86_afs.dict_size[dib], bin.readbs(l))[0]
                    d = self.intsize(d)

                    dib_out.append({x86_afs.imm:d})
                elif dib in [imm, ims]:
                    taille, fmt, t = x86mndb.get_im_fmt(m.modifs, self.opmode, dib)
                    dib_out.append({x86_afs.imm:self.intsize(struct.unpack(fmt, bin.readbs(taille))[0], dib==ims)})

                elif dib in [im1, im3]:
                    dib_out.append({im1:{x86_afs.imm:self.intsize(1)},im3:{x86_afs.imm:self.intsize(3)}}[dib])
                elif dib == rmr:
                    continue
                elif dib == r_eax:
                    mafs = dict(x86mndb.get_afs_re(x86_afs.reg_dict[x86_afs.r_eax]))
                    if m.modifs[w8]:
                        mafs[x86_afs.size] = x86_afs.u08
                    else:
                        mafs[x86_afs.size] = self.opmode

                    r = mafs

                    if len(mnemo_args):
                        if m.modifs[sw]:
                            mnemo_args = mnemo_args+[r]
                        else:
                            mnemo_args = [r]+mnemo_args
                    else:
                        dib_out.append(r)
                elif dib == mim:
                    l = struct.calcsize(x86_afs.dict_size[self.admode])
                    d = struct.unpack(x86_afs.dict_size[self.admode], bin.readbs(l))[0]
                    d = uint32(d)

                    size = [self.opmode, x86_afs.u08][m.modifs[w8]]
                    dib_out.append({x86_afs.ad:True, x86_afs.size:size, x86_afs.imm:d})
                elif dib in [r_cl, r_dx]:
                    dib_out.append(dib)

                elif dib in segm_regs:
                    size = self.opmode
                    if not dib in segm_regs:
                        log.debug('segment reg not found %s' % dib)
                        raise ValueError('segment reg not found %s' % dib)
                    r = dib
                    dib_out.append({x86_afs.ad:False,
                                    x86_afs.size : size,
                                    x86_afs.reg_dict[r]:1})
                else:
                    log.debug('bad dib!!%X' % dib)
                    raise ValueError('bad dib!!%X' % dib)

            mnemo_args+=dib_out
            log.debug("Mnemo args: %s", mnemo_args)

            for a in mnemo_args:
                for p in read_prefix:
                    if is_address(a) and p in prefix_seg.values():
                        a[x86_afs.segm]=prefix_seg_inv[p]
                        continue
                if not x86_afs.ad in a:
                    if x86_afs.imm in a:
                        a[x86_afs.size] = {
                            8:  x86_afs.u08,
                            16: x86_afs.u16,
                            32: x86_afs.u32,
                            } [a[x86_afs.imm].size]
                        a[x86_afs.ad] = False
                    else:
                        log.warn("In '%s'\n\targ=%r", self, a)
                if a[x86_afs.ad] == True:
                    if m.name in ['lea'] + mnemo_prefetch:
                        a[x86_afs.size] = True
                    else:
                        a[x86_afs.ad] = a[x86_afs.size]


            t_len = bin.offset-init_offset
            bin.offset = init_offset
            bytes_ret = bin.readbs(t_len)
            self.offset = init_offset
            self.l = t_len
            self.b = bytes_ret
            self.m = m
            self.arg = mnemo_args
            self.prefix = read_prefix

            self.special_opcodes()
            return True

        except IOError:
            log.warning( "cannot dis: not enougth bytes")
            return None

    def special_opcodes(self):
            #XXX really need to include this in disasm
            x_0f_ae = {
                'xrstor':   x86mndb.lfence_m,
                'xsaveopt': x86mndb.mfence_m,
                'clflush':  x86mndb.sfence_m,
                }
            if self.m.name in x_0f_ae:
                if not len(self.arg) or not self.arg[0]['ad']:
                    self.m = x_0f_ae[self.m.name]
                    self.arg = []
            if self.opmode == u16 and self.m.name == "pushfd":
                self.m = x86mndb.pushfw_m
            if self.opmode == u16 and self.m.name == "popfd":
                self.m = x86mndb.popfw_m
            if self.m.name.startswith("lods"):
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m = x86mndb.lodsw_m
                    self.prefix = [_ for _ in self.prefix if _ != 0x66]
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_esi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_ds)}]
            if self.m.name.startswith("stos"):
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m = x86mndb.stosw_m
                    self.prefix = [_ for _ in self.prefix if _ != 0x66]
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_edi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_es)}]
            if self.m.name != "movsx" and self.m.name.startswith("movs") and len(self.arg) == 0:
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m  = x86mndb.movsw_m
                    self.prefix = [_ for _ in self.prefix if _ != 0x66]
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_edi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_es)},

                            {x86_afs.reg_dict[x86_afs.r_esi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_ds)}]
            if self.m.name.startswith("cmps"):
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m  = x86mndb.cmpsw_m
                    self.prefix = [_ for _ in self.prefix if _ != 0x66]
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_edi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_es)},

                            {x86_afs.reg_dict[x86_afs.r_esi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_ds)}]
            if self.m.name.startswith("scas"):
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m  = x86mndb.scasw_m
                    self.prefix = [_ for _ in self.prefix if _ != 0x66]
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_edi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_es)}]
            if self.m.modifs[sd] == True:
                for a in self.arg:
                    if a[x86_afs.size] == x86_afs.u32:
                        a[x86_afs.size] = x86_afs.f32

    def parse_mnemo(self, l):
        wordsplitted = shlex.shlex(l)
        wordsplitted.wordchars += '.@'
        prefix = []
        args = ['']
        for name in wordsplitted:
            if name in prefix_dic:
                prefix.append(prefix_dic[name])
                continue
            break
        else:
            raise ValueError('cannot parse mnemo? %s' % l)
        for tok in wordsplitted:
            if tok == ',':
                args.append('')
            else:
                args[-1] += ' ' + tok
        if args == ['']:
            args = []
        from miasmX.core.parse_ad import parse_ad
        args = [ parse_ad(a) for a in args ]
        if name == 'push' and args[0][x86_afs.size] == x86_afs.u16:
            a = args[0]
            a[x86_afs.ad] = False
            if is_imm(a):
                args[0][x86_afs.ad] = False
        if name.startswith('test') or name.startswith('xchg'):
            # Be liberal in what we accept, because old clang has bugs
            if args[1][x86_afs.ad] != False: args.reverse()
        if name == 'fwait': name = 'wait'
        return prefix, name, args
    parse_mnemo = classmethod(parse_mnemo)

    def arg_set_numpy_imm(self, args):
        if len([ a for a in args if x86_afs.imm in a ]) == 0:
            return
        size = set([ a[x86_afs.size] for a in args ])
        size.discard(True)
        size.discard(x86_afs.u32)
        if len(size) == 1:
            size = size.pop()
        elif len(size) == 0:
            size = x86_afs.u32
        if size in [mm, xmm]:
            size = x86_afs.u08
        for a in args:
            if x86_afs.imm in a:
                if a[x86_afs.ad]: t_size = tab_size2int[x86_afs.u32]
                else:             t_size = tab_size2int[size]
                a[x86_afs.imm] = t_size(a[x86_afs.imm])
    arg_set_numpy_imm = classmethod(arg_set_numpy_imm)

    def normalize_args(self, name, args):
        # special case ommiting 10 as argument
        if len(args) == 0 and name in ["aad", "aam"]:
            args.append( {x86_afs.imm:10, x86_afs.ad: False, x86_afs.size: x86_afs.u32} )
        # special case ommiting 1 as argument
        if len(args) == 1 and name in ["sal", "sar", "shl", "shr", "ror", "rol"]:
            args.append( {x86_afs.imm: 1, x86_afs.ad: False, x86_afs.size: x86_afs.u32} )
        # special case ommiting cl as argument
        if len(args) == 2 and name in ["shrd", "shld"]:
            args.append( {1: 1, x86_afs.ad: False, x86_afs.size: x86_afs.u08} )
        # special case ommiting st(1) as argument
        if len(args) == 0 and name in float_st_st1:
            args.append( {1: 1, x86_afs.ad: False, x86_afs.size: x86_afs.f32} )
        # special case ommiting st(0) as argument
        if len(args) == 1 and name in float_arith and args[0][x86_afs.ad] == False:
            args.insert(0, {0: 1, x86_afs.ad: False, x86_afs.size: x86_afs.f32})
        # special case where the 'ax' argument should be implicit
        if len(args) == 1 and name in ["fnstsw"] and dict([ _ for _ in args[0].items() if _[0] != 'txt']) == {0: 1, x86_afs.ad: False, x86_afs.size: x86_afs.u16}:
            args[0:1] = []
        # special case when the first argument should be omitted
        if len(args) == 2 and name in float_st_mnemo:
            args[0:1] = []
        # special case when the second argument should be omitted
        if len(args) == 2 and name in float_arith_p:
            args[1:2] = []
        # special case when the argument should be omitted
        if len(args) == 1 and name in rep_sto_lod_sca:
            args[0:2] = []
        # special case when both arguments should be omitted
        if len(args) == 2 and name in rep_mov_cmp \
                and args[0][x86_afs.size] != x86_afs.xmm \
                and args[1][x86_afs.size] != x86_afs.xmm:
            args[0:2] = []
        # "lea" has a specific syntax
        if name == "lea":
            args[1][x86_afs.size] = True
            args[1][x86_afs.ad] = x86_afs.u32
        # "prefetch" have a specific syntax
        if name in mnemo_prefetch:
            args[0][x86_afs.size] = True
            args[0][x86_afs.ad] = x86_afs.u32
        # special case when third argument is a byte
        if name in ['shufps', 'pextrw', 'pinsrw']:
            args[2][x86_afs.size] = x86_afs.u08
        if name in mnemo_sse_cmp:
            predicate = mnemo_sse_cmp_predicate.index(name[3:-2])
            args.append( {x86_afs.imm: uint8(predicate), x86_afs.ad: False, x86_afs.size: x86_afs.u08} )
    normalize_args = classmethod(normalize_args)

    def asm_candidates(self, prefix, name, args_eval):
        # 'prefix' is a list that may be modified
        # 'args_eval' is a list whose elements can be modified
        for a in args_eval:
            if x86_afs.segm in a:
                # XXX todo hack: if only one arg, no prefix
                if len(args_eval) == 1 and not name in ['push', 'pop']:
                    continue
                #print a
                prefix.append(prefix_seg[a[x86_afs.segm]])
                del a[x86_afs.segm]
            if x86_afs.symb in a:
                log.debug('pre-assembling with symbol! %s', a[x86_afs.symb])
                if not x86_afs.imm in a:
                    a[x86_afs.imm] = 0
                del a[x86_afs.symb]
        log.info("prefix:%s", prefix)
        log.info('eval: %s', args_eval)
        #search all candidates
        log.debug('Find mnemo')
        x_0f_ae = {
            'lfence': 'xrstor',
            'mfence': 'xsaveopt',
            'sfence': 'clflush',
            }
        if name in x_0f_ae:
            assert args_eval == []
            args_eval = [{0: 1, x86_afs.ad: False, x86_afs.size: x86_afs.u32}]
            name = x_0f_ae[name]
        if name == 'movhlps': name = 'movlps'
        if name == 'movlhps': name = 'movhps'
        if name == 'movq':
            # Special case
            # 0f d6 'movq'
            # 0f 7e 'mov#d#'
            # 0f 6f 'mov#qa#'
            args_size = [_[x86_afs.size] for _ in args_eval]
            if   x86_afs.mm in args_size: # one, or both
                name = 'mov#qa#'
            elif args_size[0] == x86_afs.xmm: # first, or both
                name = 'mov#d#'
                prefix.append(0xF3)
            elif args_size[1] == x86_afs.xmm: # second only
                name = 'movq'
                prefix.append(0x66)
            else:
                NEVER
        elif name == 'cmpsd' and len(args_eval) == 0:
            pass
        elif name in mnemo_mmx_hash:
            mmx_name = mnemo_mmx_hash[name]
            if name == 'movsd':
                # Special case: string instruction
                if len(args_eval) < 2:
                    mmx_name = name
            log.debug('MMX mnemo %r => %r', name, mmx_name)
            if name.startswith('cmp'):
                name = 'cmp' + name[-2:]
            p = [_ for _ in range(4) if name == mmx_set_suffix(mmx_name, _)]
            if len(p) == 1 and p[0] > 0:
                prefix.append(mmx_prefixes[p[0]])
            elif p == [0]:
                pass
            elif p == [0, 1]:
                for a in args_eval:
                    if a[x86_afs.size] == x86_afs.xmm:
                        prefix.append(mmx_prefixes[1])
                        break
            elif mmx_name == name:
                pass # movsd string instruction
            else:
                log.error('MMX prefix %r!=%r %r', name, mmx_name, p)
            log.debug('MMX prefix %r', prefix)
            name = mmx_name
        candidate = x86mndb.find_mnemo(name)
        if not candidate:
            log.warning("no mnemonic found")

        can_be_16_32 = True
        log.debug("candi:")
        for c in candidate:
            if c.modifs[sd] or c.modifs[wd]:
                can_be_16_32 = False
            log.debug( c)

        #test for 16/32 bit mode
        if can_be_16_32:
            self.mnemo_mode = None
            for a in args_eval:
                if (is_reg(a)) and a[x86_afs.size] == u32:
                    self.mnemo_mode = u32
                    break
                if (name == 'push' or (is_reg(a) or is_address(a))) \
                        and a[x86_afs.size] == u16 and self.mnemo_mode is None:
                    self.mnemo_mode = u16
                    break

            if self.mnemo_mode is None:
                self.mnemo_mode = u32
            if self.mnemo_mode == u16:
                # 16 bit mode detected
                prefix.append(0x66)
                if  name in ["movzx", "movsx"]:
                    if args_eval[0][x86_afs.size] == u16:
                        args_eval[0][x86_afs.size] = u32
                        if args_eval[0][x86_afs.ad]:
                            args_eval[0][x86_afs.ad] = u32
                else:
                    for a in args_eval:
                        if a[x86_afs.size] == u16:
                            a[x86_afs.size] = u32
                            if a[x86_afs.ad]:
                                a[x86_afs.ad] = u32
        else:
            self.mnemo_mode = u32

        log.info('eval2: %s', args_eval)

        modifs = dict([[x, None] for x in [w8, se, sw, ww, sg, dr, cr, ft, w64, sd, wd]])
        modifs[sw] = False

        #spot dr/cr regs
        for a in args_eval:
            for x in a:
                if type(x) == int and x>=0x100:
                    tmp = a[x]
                    for y in mask_drcrsg:
                        if x & mask_drcrsg[y]:
                            modifs[y] = True

        candidate_out = []
        for c in candidate:
            if (modifs[cr] or c.modifs[cr]) and modifs[cr] != c.modifs[cr]:
                continue
            if (modifs[dr] or c.modifs[dr]) and modifs[dr] != c.modifs[dr]:
                continue
            if (modifs[sg] or c.modifs[sg]) and modifs[sg] != c.modifs[sg]:
                continue

            args_sample = [dict(x) for x in args_eval]

            afs, dibs = c.afs, c.rm
            log.debug("Candidate: %s", c)

            parsed_args = []
            parsed_val = [{}]
            out_opc = [c.opc[:]]
            opc_add = []

            good_c = True
            dib_out = []
            for dib in dibs:
                if dib in [u08, s08, u16, s16, u32, s32]:
                    index_im = [-1, 0][afs == noafs]
                    if name in ['shld', 'shrd'] or '#' in name:
                        index_im = -1

                    if len(args_sample)<=0:
                        good_c = False
                        break
                    if not x86_afs.imm in args_sample[index_im] or args_sample[index_im][x86_afs.ad]:
                        log.debug("not imm 1: %s", args_sample[index_im])
                        good_c = False
                        break

                    if self.mnemo_mode !=u32:
                        if dib == u32:
                            dib = u16
                        if dib == s32:
                            dib = s16

                    size = dib

                    v = check_imm_size(args_sample[index_im][x86_afs.imm], size)
                    if v is None:
                        log.debug("cannot encode this val in size %s %x!", size, args_sample[index_im][x86_afs.imm])
                        good_c= False
                        break

                    args_sample[index_im][x86_afs.size] = size
                    args_sample[index_im][x86_afs.imm] = tab_size2int[size](v)

                    opc_add.append({x86_afs.size:size, x86_afs.imm:args_sample[index_im][x86_afs.imm]})
                    r = args_sample[index_im]
                    del args_sample[index_im]
                    dib_out.append(r)

                elif dib in [im1, im3]:
                    if x86_afs.imm in args_sample[-1] and args_sample[-1][x86_afs.imm] =={im1:1,im3:3}[dib]:
                        dib_out.append(args_sample.pop())
                    else:
                        log.debug("not im val fixed")
                        good_c = False
                        break

                elif dib in [imm, ims]:
                    if len(args_sample)<=0:
                        good_c = False
                        break
                    if not x86_afs.imm in args_sample[-1] or args_sample[-1][x86_afs.ad]:
                        log.debug("not imm 2")
                        good_c = False
                        break
                    taille, fmt, t = x86mndb.get_im_fmt(c.modifs, self.admode, dib)
                    r = args_sample.pop()
                    v = check_imm_size(r[x86_afs.imm], t)
                    if v is None:
                        log.debug("cannot encode this val in size %s %x!", t, int(r[x86_afs.imm]))
                        good_c= False
                        break
                    r[x86_afs.imm] = tab_size2int[t](v)
                    opc_add.append({x86_afs.size:t, x86_afs.imm:r[x86_afs.imm]})

                    if c.modifs[se]:
                        r[x86_afs.size] = r[x86_afs.size]
                        r[x86_afs.imm] = tab_size2int[r[x86_afs.size]](r[x86_afs.imm])
                    dib_out.append(r)

                elif dib == rmr:
                    continue

                elif dib == r_eax:
                    if not args_sample or args_sample[0][x86_afs.ad]:
                        log.debug("not r_eax1")
                        good_c = False
                        break
                    size = args_sample[0][x86_afs.size]

                    if not x86mndb.check_size_modif(size, c.modifs):
                        log.debug(' bad reg size')
                        good_c = False
                        break
                    if c.modifs[sw]:
                        index = 1
                        if len(args_sample) !=2:
                            raise ValueError("sw in r_eax zarb")
                    else:
                        index = 0
                    if not x86_afs.reg_dict[x86_afs.r_eax] in args_sample[index]:
                        log.debug("not r_eax2")
                        good_c = False
                        break
                    #add front
                    if size == x86_afs.u32:
                        args_sample[index][x86_afs.size] = self.mnemo_mode
                    r = args_sample[index]
                    del(args_sample[index])
                    if len(args_sample) and not c.modifs[sw]:
                        parsed_args.append(r)
                    else:
                        dib_out.append(r)

                elif dib in [r_cl, r_dx]:
                    index_im = [-1, 0][dib == r_dx]
                    dib_tmp = dict(dib)
                    del(dib_tmp[x86_afs.size])
                    del(args_sample[index_im][x86_afs.size])
                    args_sample[index_im].pop('txt', None)
                    #XXX in al, dx => spot 16 bit manip; concat 66 bug
                    if dib_tmp != args_sample[index_im]:
                        log.debug("not r_cl d_dx")
                        good_c = False
                        break

                    r = args_sample[index_im]
                    del args_sample[index_im]
                    dib_out.append(r)

                elif dib == mim:
                    if len(args_sample)<=0:
                        good_c = False
                        break
                    r = args_sample[0]
                    if not x86_afs.imm in r or not x86_afs.ad in r or not r[x86_afs.ad]:
                        log.debug("not mim")
                        good_c = False
                        break

                    for k in r:
                        if not k in [x86_afs.imm, x86_afs.ad, x86_afs.size]:
                            log.debug("mim: cannot encode reg ")
                            good_c = False
                            break

                    a_mem = {x86_afs.size:u32, x86_afs.imm:uint32(r[x86_afs.imm]), x86_afs.ad:r[x86_afs.ad]}
                    opc_add.append(a_mem)
                    del args_sample[0]
                    a_pmem = dict(a_mem)
                    a_pmem[x86_afs.ad] = u32
                    parsed_args.append(a_pmem)

                elif dib in segm_regs:
                    good_c = False
                    for reg_code in x86_afs.reg_dict:
                        if x86_afs.reg_dict[reg_code] in args_sample[0]:
                            if reg_code == dib:
                                del args_sample[0]
                                good_c = True
                                break

                else:
                    raise ValueError('bad dib!! %r' % dib)

            if not good_c:
                continue

            log.debug("***pass dib***")
            log.debug("Modifs: %s", modifs)
            log.debug("Dibs: %s", dibs)
            log.debug("Afs: %s", afs)
            log.debug("Args: %s", args_sample)

            if afs in [d0, d1, d2, d3, d4, d5, d6, d7]:
                if len(args_sample)!=1:
                    log.debug('%s bad arg num1', c)
                    continue
                a = args_sample[0]
                if rmr in dibs and not x86_afs.imm in a and a[x86_afs.ad] == False:
                    log.info("No register should be encoded here")
                    continue
                if a[x86_afs.ad]:
                    size = a[x86_afs.ad]
                    if c.name in ("fxsave", "fxrstor", "ldmxcsr", "stmxcsr",
                                  "xsave", "xrstor", "xsaveopt", "clflush"):
                        size = 512
                        size = {
                            False: x86_afs.u64,
                            True:  x86_afs.f32,
                            None:  x86_afs.u32,
                            }[c.modifs[sd]]
                    elif c.modifs[sd] is not None:
                        size = {x86_afs.f80:x86_afs.f80, x86_afs.u16:x86_afs.u16, x86_afs.u32:x86_afs.f32, x86_afs.f32:x86_afs.f32, x86_afs.f64:x86_afs.f64}[size]
                else:
                    size = a[x86_afs.size]
                if not x86mndb.check_size_modif(size, c.modifs):
                    log.debug(' bad size digit')
                    continue
                out_opc, parsed_val = x86mndb.forge_opc(out_opc, dict(a))
                if out_opc is None or parsed_val is None:
                    log.debug('cannot encode opc (dX afs)')
                    continue
                parsed_args.append(a)

            elif afs == reg:
                if len(args_sample)!=1:
                    log.debug('%s bad arg num', c)
                    continue
                a = args_sample[0]
                if  a[x86_afs.ad]:
                    log.debug(' address in reg')
                    continue
                size = a[x86_afs.size]
                if not x86mndb.check_size_modif(size, c.modifs):
                    log.debug(' bad size reg')
                    continue
                k = [x for x in a.keys() if type(x) == int]
                if a[x86_afs.ad] or x86_afs.imm in a or len(k)!=1:
                    log.debug('bad a2 %s', a)
                    continue
                out_opc[0][-1]+=k[0]
                parsed_args.append(a)

            elif not afs in [ noafs, cond ]:
                raise ValueError('unknown afs: %s' % afs)

            elif not rmr in c.rm:
                if len(args_sample)!=0:
                    log.debug('%s bad arg num no.rmr', c)
                    continue

            elif afs == cond and len(args_sample)==1:
                a = args_sample[0]
                if a[x86_afs.ad]:
                    size = a[x86_afs.ad]
                else:
                    size = a[x86_afs.size]
                out_opc, parsed_val = x86mndb.forge_opc([[0]], dict(a))
                if out_opc is None or parsed_val is None:
                    log.debug('cannot encode opc (cond afs)')
                    continue
                for i in range(len(out_opc)):
                    out_opc[i] = c.opc + out_opc[i]
                parsed_args.append(a)

            else:
                swap_args = c.modifs[sw]
                if name == 'mov#d#' and prefix == [0xF3]:
                    swap_args = not swap_args
                    if swap_args: continue
                if len(args_sample)!=2:
                    log.debug('%s bad arg num', c)
                    continue
                a1 = args_sample[1]
                a2 = args_sample[0]
                if swap_args and a1[x86_afs.ad]:
                    log.debug(' bad sw rmr 1')
                    continue
                if not swap_args and a2[x86_afs.ad]:
                    log.debug(' bad sw rmr 2')
                    continue
                if not a1[x86_afs.ad] and x86_afs.imm in a1:
                    log.debug('Imm in rmr 1')
                    continue
                if not a2[x86_afs.ad] and x86_afs.imm in a2:
                    log.debug('Imm in rmr 2')
                    continue

                size = [ a2[x86_afs.size], a1[x86_afs.size] ]

                if not (imm in dibs or ims in dibs):
                    if swap_args:
                        size.reverse()

                    if c.modifs[se]!=None:
                        if size[1] != [x86_afs.u08, x86_afs.u16][c.modifs[se]]:
                            log.debug(' bad size se rmr')
                            continue
                    elif not x86mndb.check_size_modif(size[0], c.modifs):
                        log.debug(' bad size rmr')
                        continue

                #reg, modr
                if swap_args:
                    tmp_order = [a2,a1]
                else:
                    tmp_order = [a1,a2]

                for y in mask_drcrsg:
                    if not modifs[y]:
                        continue
                    for x in tmp_order[1]:
                        if not type(x) == int:
                            continue
                        if not x&mask_drcrsg[y]:
                            log.debug('cr dr sg not found in reg')
                            good_c = False
                            break
                        tmp = tmp_order[1][x]
                        del(tmp_order[1][x])
                        tmp_order[1][x&0xFF] = tmp

                if not good_c:
                    continue

                out_opc, parsed_val = x86mndb.forge_opc(out_opc, *tmp_order)
                if out_opc is None or parsed_val is None:
                    log.debug('cannot encode opc (noafs)')
                    continue

                if c.modifs[se]:
                    size[1] = size[0]
                if size[0] != size[1] and not name in ['movzx', 'movsx', 'pmovmskb', '#p#extrb', '#p#extrd', '#p#extrw', '#p#insrb', '#p#insrd', '#p#insrw', 'movmskp#S#', 'cvt#pi2ps', 'cvtt#ps2pi', 'cvt#ps2pi'] and not '##' in name:
                    if tmp_order[0][x86_afs.ad]:
                        size[1] = size[0]
                    elif name == 'mov#d#' and size[0] in [x86_afs.mm, x86_afs.xmm]:
                        pass
                    else:
                        log.debug('uncompatible size in rmr for %s', name)
                        continue
                a1[x86_afs.size] = size[1]

                parsed_args += [a2, a1]

            for do in dib_out:
                parsed_args.append(do)

            if self.mnemo_mode == u16:
                for a in parsed_args:
                    if not x86_afs.size in a:
                        a[x86_afs.size] = u16
                        continue
                    if a[x86_afs.size] == u32:
                        a[x86_afs.size] = u16
                        if a[x86_afs.ad]:
                            a[x86_afs.ad] = u16

            log.debug( "ok")
            log.debug(out_opc)
            log.debug(parsed_val)
            log.debug(parsed_args)
            for i in range(len(out_opc)):
                candidate_out.append((c, parsed_args, (out_opc[i], parsed_val[i], opc_add), self.mnemo_mode))
        return candidate_out

    def _asm(self, l, symbol_off_out):
        log.debug("asm: %s", l)

        prefix, name, args = x86_mn.parse_mnemo(l)
        if name == "rep":
            # Special case: gcc can output lines with only 'rep'
            # then we need to merge it with the next line
            # http://mikedimmick.blogspot.fr/2008/03/what-heck-does-ret-mean.html
            return prefix, []

        log.debug("name: %s", name)
        log.debug("args: %s", args)
        
        self.normalize_args(name, args)
        instr = x86_mn()
        co = instr.asm_candidates(prefix, name, [a.copy() for a in args])
        ac = self.asm_all_candidate(prefix, co)
        for x in ac:
            symbol_off_out.append(x[1])
        return [x[0] for x in ac]

    def asm_all_candidate(self, prefix, candidate_out):
        symbol_off = []
        hex_candidate = []
        for _, _, opc_o, mnemo_mode in candidate_out:
            out_opc = prefix[:]
            out_opc += opc_o[0]
            out_byte = struct.pack("B"*len(out_opc),*out_opc)

            # positions of the arguments...
            # needed if they contain symbols, to compute the relocation index
            # TODO: compute the pair (r_type, position)
            symbol_off.append([])

            val_add = [opc_o[1]]+opc_o[2]
            for c in val_add:
                if c == {}:
                    continue
                symbol_off[-1].append(len(out_byte))
                if mnemo_mode == 'u16' and c[x86_afs.size] in [u32, s32] and not c.get(x86_afs.ad,False):
                    out_byte+=struct.pack(x86_afs.dict_size[mnemo_mode], int(c[x86_afs.imm]&0xffff))
                elif c[x86_afs.size] in [u08, s08, u16, s16, u32, s32]:
                    out_byte+=struct.pack(x86_afs.dict_size[c[x86_afs.size]], int(c[x86_afs.imm]))
                else:
                    raise ValueError('bad size in asm! %s' % c)

            hex_candidate.append(out_byte)
            log.info( hexdump(out_byte))
        return list(zip(hex_candidate, symbol_off))
        # Don't order by length; we keep the order of candidate_out
        # This is OK because of the way the addop are ordered
        all_candidate = sorted(zip(hex_candidate, symbol_off),
            key=lambda x:len(x[0]))
        return all_candidate
    asm_all_candidate = classmethod(asm_all_candidate)


x86mnemo = x86_mn

if __name__ == '__main__':
    test_out = []
    log.setLevel(logging.DEBUG)



    instr = x86mnemo.dis('0f6ec5'.replace(' ', '').decode('hex'))
    print(instr)
    print(instr.arg)
    print(instr.l)
    print(instr.opmode, instr.admode)


    instr = x86mnemo.dis('0f7ec5'.replace(' ', '').decode('hex'))
    print(instr)
    print(instr.arg)
    print(instr.l)
    print(instr.opmode, instr.admode)


    fds

    instr = x86mnemo.dis('67e1fa'.replace(' ', '').decode('hex'))
    print(instr)
    print(instr.arg)
    print(instr.l)
    print(instr.opmode, instr.admode)
    fds


    instr = x86mnemo.dis('0fa9'.replace(' ', '').decode('hex'),
                         {"admode":x86_afs.u16,"opmode":x86_afs.u16})
    print(instr)
    print(instr.arg)
    print(instr.l)
    print(instr.opmode, instr.admode)
    fds


    instr = x86mnemo.dis('ea21060000'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print(instr)
    print(instr.arg)
    print(instr.l)
    print(instr.opmode, instr.admode)
    fds


    instr = x86mnemo.dis('0fbe13'.replace(' ', '').decode('hex'),)
                         #admode=x86_afs.u16,
                         #opmode=x86_afs.u16)
    print(instr)
    print(instr.arg)
    print(instr.l)
    print(instr.arg[1]["imm"].__class__)
    print(instr.opmode, instr.admode)
    fds



    instr = x86mnemo.dis('038678ff'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print(instr)
    print(instr.arg)
    print(instr.l)
    print(instr.arg[1]["imm"].__class__)
    print(instr.opmode, instr.admode)
    fds


    instr = x86mnemo.dis('8946da'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print(instr)
    print(instr.arg)
    print(instr.l)
    print(instr.opmode, instr.admode)
    fds

    instr = x86mnemo.dis('66c74440ffffffff'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print(instr)
    print(instr.arg)
    print(instr.l)
    print(instr.opmode, instr.admode)
    fds

    instr = x86mnemo.dis('c57608'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('66af'.replace(' ', '').decode('hex'))
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('64a100000000'.replace(' ', '').decode('hex'))
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('8d03'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('669d'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds



    instr = x86mnemo.dis('07'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('66A5'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('DB 28'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('DB 6D 08'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('C7 44 24 08 00 00 00 00'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('F0 65 0F B1 0D 84 00 00 00'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('F0 65 83 0D 84 00 00 00 10'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    print(instr.l)
    fds

    instr = x86mnemo.dis('65 C7 05 28 02 00 00 FF FF FF FF'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    fds

    instr = x86mnemo.dis('66ab'.decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
    fds

    instr = x86mnemo.dis('6681384D5A0000'.decode('hex'), admode=x86_afs.u32)
    print(instr)
    print(instr.arg)
