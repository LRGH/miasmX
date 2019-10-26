#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
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
from elfesteem import *
from elfesteem import pe
from elfesteem import cstruct

from miasm.arch.ia32_arch import *
from miasm.tools.emul_helper import *
from miasm.arch.ia32_sem import *
import struct
import miasm.core.asmbloc
import miasm.core.bin_stream
import os
import re
try:
    from  miasm.tools import to_c_helper
except ImportError:
    print "WARNING: cannot import to_c_helper, skipping"
from miasm.core import bin_stream
from collections import defaultdict

pe_cache = {}
def pe_from_name(n):
    global pe_cache

    my_path = 'win_dll/'
    all_pe = os.listdir(my_path)
    if not n in all_pe:
        print 'cannot find PE', n
        return None

    pe_name = my_path+n
    if pe_name in pe_cache:
        return pe_cache[pe_name]
    e = pe_init.PE(open(pe_name, 'rb').read())
    pe_cache[pe_name] = e
    return e


def func_from_import(pe_name, func):
    e = pe_from_name(pe_name)

    if not e or not e.DirExport:
        print 'no export dir found'
        return None, None


    found = None
    if type(func) is str:
        for i, n in enumerate(e.DirExport.f_names):
            if n.name.name == func:
                found = e.DirExport.f_address[e.DirExport.f_nameordinals[i].ordinal].rva
                break

    elif type(func) in [int, long]:
        for i, n in enumerate(e.DirExport.f_names):
            if e.DirExport.f_nameordinals[i].ordinal+e.DirExport.expdesc.base == func:
                found = e.DirExport.f_address[e.DirExport.f_nameordinals[i].ordinal].rva
                break
    else:
        raise ValueError('unknown fund type', func)

    #XXX todo: test if redirected export
    return e, found


def get_sectionname(e, offset):
    section = e.getsectionbyvad(offset)
    if section == None:
        return None
    if isinstance(e, elf_init.ELF):
        return section.sh.name
    elif isinstance(e, pe_init.PE):
        return section.name
    else:
        raise ValueError("TODO")

def is_rva_in_code_section(e, rva):
    s = e.getsectionbyrva(rva)
    return s.flags&0x20!=0

def guess_func_destack_dis(e, ad):
    job_done = set()
    symbol_pool = asmbloc.asm_symbol_pool()
    in_str = bin_stream(e.virt)

    all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, ad, job_done, symbol_pool, follow_call = False, patch_instr_symb = False)
    return guess_func_destack(all_bloc)


def guess_imports_ret_unstack(e):
    unresolved = set()
    resolved = {}
    redirected = {}
    for i,s in enumerate(e.DirImport.impdesc):
        l = "%2d %-25s %s"%(i, repr(s.dlldescname) ,repr(s))
        libname = s.dlldescname.name


        for ii, f in enumerate(s.impbynames):
            print '_'*20
            funcname = f.name


            my_e, ret = func_from_import(libname.lower(), funcname)
            if ret:
                func_addr = my_e.rva2virt(ret.rva)
                print funcname, hex(func_addr)
            else:
                print 'not found'
                continue

            #XXX python int obj len zarb bug
            imgb = my_e.NThdr.ImageBase
            if imgb>0x80000000:
                imgb-=0x40000000
                func_addr-=0x40000000
                my_e.NThdr.ImageBase = imgb

            if not is_rva_in_code_section(my_e, ret.rva):
                print "not in code section"
                continue


            ok, r = guess_func_destack_dis(my_e, func_addr)
            print funcname, 'ret', r
            if ok == True:
                resolved[(libname, funcname)] = r
            elif ok == None:
                unresolved.add((libname, funcname))
            else:
                resolved[(libname, funcname)] = r


    return resolved, unresolved, redirected


def get_import_address(e):
    import2addr = defaultdict(set)
    for i,s in enumerate(e.DirImport.impdesc):
        fthunk = e.rva2virt(s.firstthunk)
        l = "%2d %-25s %s"%(i, repr(s.dlldescname) ,repr(s))
        libname = s.dlldescname.name.lower()
        for ii, imp in enumerate(s.impbynames):
            if isinstance(imp, pe.ImportByName):
                funcname = imp.name
            else:
                funcname = imp
            l = "    %2d %-16s"%(ii, repr(funcname))
            import2addr[(libname, funcname)].add(e.rva2virt(s.firstthunk+4*ii))
    return import2addr


def get_import_address_elf(e):
    import2addr = defaultdict(set)
    for sh in e.sh:
        if not hasattr(sh, 'rel'):
            continue
        for k, v in sh.rel.items():
            import2addr[('xxx', k)].add(v.offset)
    return import2addr


def get_symbols_elf(e):
    sym2addr = {}
    for k, v in e.sh.dynsym.symbols.items():
        sym2addr[k] = v
    return sym2addr


def get_java_constant_pool(e):
    constants = {}
    for i, c in enumerate(e.hdr.constants_pool):
        constants[i+1] = c
    return constants

def guess_redirected(e, resolved, unresolved, redirected, import2addr):

    import2addr_inv = [(x[1], x[0]) for x in import2addr.items()]

    to_del = []
    for imp in redirected:
        ad = redirected[imp]
        if ad in import2addr_inv:
            my_imp = import2addr[ad]
            if not my_imp in resolved:
                continue
            else:
                resolved[my_imp] = resolved[imp]
                to_del.append(my_imp)

    redirected = [x for x in redirected if not x in to_del]
    return resolved, unresolved, redirected

if __name__ == '__main__':
    e, ret = func_from_import('hal.dll', 'KfAcquireSpinLock')
    if ret:
        print dir(ret)
        print hex(e.rva2virt(ret.rva))

def get_imp_to_dict(e):
    imp2ad = get_import_address(e)
    imp_d = {}
    for libf, ads in imp2ad.items():
        for ad in ads:
            libname, f = libf
            imp_d[ad] = libf
    return imp_d




def get_imp_bloc(all_bloc, new_lib, imp_d, symbol_pool):
    f_imps = []
    symb_equiv = {}
    for b in all_bloc:
        for l in b.lines:
            for a in l.arg:
                if not x86_afs.ad in a or not a[x86_afs.ad]:
                    continue
                print a
                if not x86_afs.imm in a:
                    continue
                ad = a[x86_afs.imm]
                if not ad in imp_d:
                    continue
                print 'spot', ad, l
                lab = symbol_pool.getby_offset_create(ad)
                print lab


                l = symbol_pool.getby_offset(ad)
                print "ioioio", l
                l.offset = None

                a[x86_afs.symb] = {lab.name:1}
                print a
                del a[x86_afs.imm]

                libname, func = imp_d[ad]
                print func
                new_lib.append(
                    ({"name":libname,
                      "firstthunk":None},
                     [func]),
                    )
                f_imps.append(func)
                symb_equiv[func] = l
    return f_imps, symb_equiv


def code_is_line(e, ad):
    job_done = set()
    in_str = bin_stream.bin_stream(e.virt)
    symbol_pool = asmbloc.asm_symbol_pool()
    all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, ad, job_done, symbol_pool, bloc_wd = 2)
    if len(all_bloc) !=1:
        return None
    if len(all_bloc[0].lines)!=1:
        return None
    return all_bloc

def is_jmp_imp(l, imp_d):
    if not l.m.name == 'jmp':
        return False
    if not is_address(l.arg[0]):
        return False
    ad = dict(l.arg[0])
    del ad[x86_afs.ad]
    if not is_imm(ad):
        return False
    print ad
    i = ad[x86_afs.imm]
    if not i in imp_d:
        return False
    print imp_d[i]
    return imp_d[i]


def code_is_jmp_imp(e, ad, imp_d):
    all_bloc = code_is_line(e, ad)
    if not all_bloc:
        return None
    l = all_bloc[0].lines[0]
    return is_jmp_imp(l, imp_d)


def test_ret_and_cc(in_str, ad):
    while in_str[ad] == "\xCC":
        ad -=1
    return in_str[ad] == '\xC3' or in_str[ad-2] == "\xC2"

# giving e and address in function guess function start
def guess_func_start(in_str, line_ad, max_offset = 0x200):
    ad = line_ad+1
    done = False
    func_addrs = set()
    symbol_pool = asmbloc.asm_symbol_pool()
    all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, line_ad,
                                    func_addrs, symbol_pool)
    while not done:
        ad_found = None
        while ad > line_ad - max_offset:
            ad-=1
            ####### heuristic CC pad #######
            if in_str[ad] == "\xCC":
                if in_str[((ad+3)&~3)-1] == "\xCC":
                    ad_found = ((ad+3)&~3)
                    if test_ret_and_cc(in_str, ad_found):
                        break
                    else:
                        continue
                else:
                    continue
            l = x86_mn.dis(in_str[ad:ad+15])
            if not l:
                continue
            if l.m.name in ["ret"]:
                ad_found = ad+l.l
                break
        if not ad_found:
            print 'cannot find func start'
            return None
        while in_str[ad_found] == "\xCC":
            ad_found+=1
        # lea eax, [eax]
        if in_str[ad_found:ad_found+3] == "\x8D\x40\x00":
            ad_found += 3

        job_done = set()
        symbol_pool = asmbloc.asm_symbol_pool()
        all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, ad_found, job_done, symbol_pool)
        if func_addrs.issubset(job_done):
            return ad_found

def get_nul_term(e, ad):
    out = ""
    while True:
        c = e.virt[ad]
        if c == None:
            return None
        if c == "\x00":
            break
        out+=c
        ad+=1
    return out

#return None if is not str
def guess_is_string(out):
    if out == None or len(out) == 0:
        return None
    cpt = 0
    for c in out:
        if c.isalnum():
            cpt+=1
    if cpt * 100 / len(out) > 40:
        return out
    return None


def get_guess_string(e, ad):
    s = get_nul_term(e, ad)
    return guess_is_string(s)

def is_redirected_export(e, ad):
    # test is ad points to code or dll name
    out = ''
    for i in xrange(0x200):
        c = e.virt[ad+i]
        if c == "\x00":
            break
        out += c
        if not (c.isalnum() or c in "_.-+*$@&#()[]={}"):
            return False
    if not "." in out:
        return False
    i = out.find('.')
    return out[:i], out[i+1:]


def canon_libname_libfunc(libname, libfunc):
    dn = libname.split('.')[0]
    if type(libfunc) == str:
        return "%s_%s"%(dn, libfunc)
    else:
        return str(dn), libfunc

class libimp:
    def __init__(self, lib_base_ad = 0x77700000):
        self.name2off = {}
        self.libbase2lastad = {}
        self.libbase_ad = lib_base_ad
        self.lib_imp2ad = {}
        self.lib_imp2dstad = {}
        self.fad2cname = {}
        self.fad2info = {}

    def lib_get_add_base(self, name):
        name = name.lower().strip(' ')
        if not "." in name:
            print 'warning adding .dll to modulename'
            name += '.dll'
            print name

        if name in self.name2off:
            ad = self.name2off[name]
        else:
            ad = self.libbase_ad
            print 'new lib', name, hex(ad)
            self.name2off[name] = ad
            self.libbase2lastad[ad] = ad+0x1
            self.lib_imp2ad[ad] = {}
            self.lib_imp2dstad[ad] = {}
            self.libbase_ad += 0x1000
        return ad

    def lib_get_add_func(self, libad, imp_ord_or_name, dst_ad = None):
        if not libad in self.name2off.values():
            raise ValueError('unknown lib base!', hex(libad))

        #test if not ordinatl
        #if imp_ord_or_name >0x10000:
        #    imp_ord_or_name = vm_get_str(imp_ord_or_name, 0x100)
        #    imp_ord_or_name = imp_ord_or_name[:imp_ord_or_name.find('\x00')]


        #/!\ can have multiple dst ad
        if not imp_ord_or_name in self.lib_imp2dstad[libad]:
            self.lib_imp2dstad[libad][imp_ord_or_name] = set()
        self.lib_imp2dstad[libad][imp_ord_or_name].add(dst_ad)


        if imp_ord_or_name in self.lib_imp2ad[libad]:
            return self.lib_imp2ad[libad][imp_ord_or_name]
        #print 'new imp', imp_ord_or_name, dst_ad
        ad = self.libbase2lastad[libad]
        self.libbase2lastad[libad] += 0x11 # arbitrary
        self.lib_imp2ad[libad][imp_ord_or_name] = ad

        name_inv = dict([(x[1], x[0]) for x in self.name2off.items()])
        c_name = canon_libname_libfunc(name_inv[libad], imp_ord_or_name)
        self.fad2cname[ad] = c_name
        self.fad2info[ad] = libad, imp_ord_or_name
        return ad

    def check_dst_ad(self):
        for ad in self.lib_imp2dstad:
            all_ads = self.lib_imp2dstad[ad].values()
            all_ads.sort()
            for i, x in enumerate(all_ads[:-1]):
                if x == None or all_ads[i+1] == None:
                    return False
                if x+4 != all_ads[i+1]:
                    return False
        return True

    def add_export_lib(self, e, name):
        # will add real lib addresses to database
        if name in self.name2off:
            ad = self.name2off[name]
        else:
            print 'new lib', name
            ad = e.NThdr.ImageBase
            libad = ad
            self.name2off[name] = ad
            self.libbase2lastad[ad] = ad+0x1
            self.lib_imp2ad[ad] = {}
            self.lib_imp2dstad[ad] = {}
            self.libbase_ad += 0x1000

            ads = get_export_name_addr_list(e)
            todo = ads
            done = []
            while todo:
                #for imp_ord_or_name, ad in ads:
                imp_ord_or_name, ad = todo.pop()

                # if export is a redirection, search redirected dll
                # and get function real addr
                ret = is_redirected_export(e, ad)
                if ret:
                    exp_dname, exp_fname = ret
                    #print "export redirection", imp_ord_or_name
                    #print "source", exp_dname, exp_fname
                    exp_dname = exp_dname+'.dll'
                    exp_dname = exp_dname.lower()
                    # if dll auto refes in redirection
                    if exp_dname == name:
                        libad_tmp = self.name2off[exp_dname]
                        if not exp_fname in self.lib_imp2ad[libad_tmp]:
                            # schedule func
                            todo = [(imp_ord_or_name, ad)]+todo
                            continue
                    elif not exp_dname in self.name2off:
                        raise ValueError('load %r first'%exp_dname)
                    c_name = canon_libname_libfunc(exp_dname, exp_fname)
                    libad_tmp = self.name2off[exp_dname]
                    ad = self.lib_imp2ad[libad_tmp][exp_fname]
                    #print hex(ad)
                #if not imp_ord_or_name in self.lib_imp2dstad[libad]:
                #    self.lib_imp2dstad[libad][imp_ord_or_name] = set()
                #self.lib_imp2dstad[libad][imp_ord_or_name].add(dst_ad)

                #print 'new imp', imp_ord_or_name, hex(ad)
                self.lib_imp2ad[libad][imp_ord_or_name] = ad

                name_inv = dict([(x[1], x[0]) for x in self.name2off.items()])
                c_name = canon_libname_libfunc(name_inv[libad], imp_ord_or_name)
                self.fad2cname[ad] = c_name
                self.fad2info[ad] = libad, imp_ord_or_name


    def gen_new_lib(self, e, filter=lambda x: True):
        new_lib = []
        for n, ad in self.name2off.items():
            out_ads = dict()
            for k, vs in self.lib_imp2dstad[ad].items():
                for v in vs:
                    out_ads[v] = k
            all_ads = self.lib_imp2dstad[ad].values()
            all_ads = reduce(lambda x,y:x+list(y), all_ads, [])
            all_ads = [x for x in all_ads if filter(x)]
            #print [hex(x) for x in all_ads]
            all_ads.sort()
            #first, drop None
            if not all_ads:
                continue
            for i,x in enumerate(all_ads):
                if not x in [0,  None]:
                    break
            all_ads = all_ads[i:]
            while all_ads:
                othunk = all_ads[0]
                i = 0
                while i+1 < len(all_ads) and all_ads[i]+4 == all_ads[i+1]:
                    i+=1
                funcs = [out_ads[x] for x in all_ads[:i+1]]
                if e.virt2off(othunk) != None:#e.is_in_virt_address(othunk):
                    new_lib.append(({"name":n,
                                     "firstthunk":e.virt2rva(othunk)},
                                    funcs)
                                   )
                all_ads = all_ads[i+1:]
        return new_lib

def vm_load_pe(e, align_s = True, load_hdr = True):
    aligned = True
    for s in e.SHList:
        if s.addr & 0xFFF:
            aligned = False
            break

    if aligned:
        if load_hdr:
            hdr_len = max(0x200, e.NThdr.sectionalignment)
            min_len = min(e.SHList[0].addr, hdr_len)
            pe_hdr = e.content[:hdr_len]
            pe_hdr = pe_hdr+min_len*"\x00"
            pe_hdr = pe_hdr[:min_len]
            to_c_helper.vm_add_memory_page(e.NThdr.ImageBase, to_c_helper.PAGE_READ|to_c_helper.PAGE_WRITE, pe_hdr)
        if align_s:
            for i, s in enumerate(e.SHList[:-1]):
                s.size = e.SHList[i+1].addr - s.addr
                s.rawsize = s.size
                s.offset = s.addr
            s = e.SHList[-1]
            s.size = (s.size+0xfff)&0xfffff000
        for s in e.SHList:
            data = str(s.data)
            data += "\x00"*(s.size-len(data))
            to_c_helper.vm_add_memory_page(e.rva2virt(s.addr), to_c_helper.PAGE_READ|to_c_helper.PAGE_WRITE, data)
            #s.offset = s.addr
        return

    #not aligned
    print 'WARNING pe is not aligned, creating big section'
    min_addr = None
    max_addr = None
    data = ""

    if load_hdr:
        data = e.content[:0x400]
        data += (e.SHList[0].addr - len(data))*"\x00"
        min_addr = 0

    for i, s in enumerate(e.SHList):
        if i < len(e.SHList)-1:
            s.size = e.SHList[i+1].addr - s.addr
        s.rawsize = s.size
        s.offset = s.addr

        if min_addr == None or s.addr < min_addr:
            min_addr = s.addr
        if max_addr == None or s.addr + s.size > max_addr:
            max_addr = s.addr + max(s.size, len(s.data))
    min_addr = e.rva2virt(min_addr)
    max_addr = e.rva2virt(max_addr)
    print hex(min_addr) , hex(max_addr), hex(max_addr - min_addr)


    to_c_helper.vm_add_memory_page(min_addr,
                                   to_c_helper.PAGE_READ|to_c_helper.PAGE_WRITE,
                                   (max_addr - min_addr)*"\x00")
    for s in e.SHList:
        print hex(e.rva2virt(s.addr)), len(s.data)
        to_c_helper.vm_set_mem(e.rva2virt(s.addr), str(s.data))


def vm_load_elf(e, align_s = True, load_hdr = True):
    for p in e.ph.phlist:
        if p.ph.type != 1:
            continue
        print hex(p.ph.vaddr), hex(p.ph.offset), hex(p.ph.filesz)
        data = e._content[p.ph.offset:p.ph.offset + p.ph.filesz]
        r_vaddr = p.ph.vaddr & ~0xFFF
        data = (p.ph.vaddr - r_vaddr) *"\x00" + data
        data += (((len(data) +0xFFF) & ~0xFFF)-len(data)) * "\x00"
        to_c_helper.vm_add_memory_page(r_vaddr, to_c_helper.PAGE_READ|to_c_helper.PAGE_WRITE, data)



def preload_lib(e, runtime_lib, patch_vm_imp = True):
    fa = get_import_address(e)
    dyn_funcs = {}
    #print 'imported funcs:', fa
    for (libname, libfunc), ads in fa.items():
        for ad in ads:
            ad_base_lib = runtime_lib.lib_get_add_base(libname)
            ad_libfunc = runtime_lib.lib_get_add_func(ad_base_lib, libfunc, ad)

            libname_s = canon_libname_libfunc(libname, libfunc)
            dyn_funcs[libname_s] = ad_libfunc
            if patch_vm_imp:
                to_c_helper.vm_set_mem(ad, struct.pack(cstruct.size2type[e._wsize], ad_libfunc))
    return dyn_funcs

def preload_elf(e, patch_vm_imp = True, lib_base_ad = 0x77700000):
    # XXX quick hack
    fa = get_import_address_elf(e)
    runtime_lib = libimp(lib_base_ad)

    dyn_funcs = {}
    #print 'imported funcs:', fa
    for (libname, libfunc), ads in fa.items():
        for ad in ads:
            ad_base_lib = runtime_lib.lib_get_add_base(libname)
            ad_libfunc = runtime_lib.lib_get_add_func(ad_base_lib, libfunc, ad)

            libname_s = canon_libname_libfunc(libname, libfunc)
            dyn_funcs[libname_s] = ad_libfunc
            if patch_vm_imp:
                to_c_helper.vm_set_mem(ad, struct.pack(cstruct.size2type[e.size], ad_libfunc))
    return runtime_lib, dyn_funcs


def get_export_name_addr_list(e):
    out = []
    # add func name
    for i, n in enumerate(e.DirExport.f_names):
        addr = e.DirExport.f_address[e.DirExport.f_nameordinals[i].ordinal]
        f_name = n.name.name
        #print f_name, hex(e.rva2virt(addr.rva))
        out.append((f_name, e.rva2virt(addr.rva)))

    # add func ordinal
    for i, o in enumerate(e.DirExport.f_nameordinals):
        addr = e.DirExport.f_address[o.ordinal]
        #print o.ordinal, e.DirExport.expdesc.base, hex(e.rva2virt(addr.rva))
        out.append((o.ordinal+e.DirExport.expdesc.base, e.rva2virt(addr.rva)))
    return out


class pattern_class:
    pass

class pattern_call_x86(pattern_class):
    patterns = ["\xE8"]
    @classmethod
    def test_candidate(cls, in_str, off_i, off_dst):
        off = off_i + 5 + struct.unpack('i', in_str[off_i+1:off_i+5])[0]
        #print "XXX", hex(off_i), hex(off)
        if off == off_dst:
            return off_i
        return None

class pattern_jmp_long_x86(pattern_call_x86):
    patterns = ["\xE9"]

class pattern_jmp_short_x86(pattern_call_x86):
    patterns = ["\xEB"]
    @classmethod
    def test_candidate(cls, in_str, off_i, off_dst):
        off = off_i + 2 + struct.unpack('b', in_str[off_i+1:off_i+2])[0]
        #print "XXX", hex(off_i), hex(off)
        if off == off_dst:
            return off_i
        return None


class find_pattern:
    def __init__(self, in_str, off_dst, find_class):
        import re
        self.in_str = in_str
        self.off_dst = off_dst
        if not type(find_class) is list:
            find_class = [find_class]
        self.find_classes = find_class
        self.class_index = 0
        self.ad = 0
    def next(self):
        while self.class_index < len(self.find_classes):
            find_class = self.find_classes[self.class_index]
            for p in find_class.patterns:
                while True:
                    #off_i = self.my_iter.next().start()
                    self.ad = self.in_str.find(p, self.ad)
                    if self.ad == -1:
                        break
                    off = find_class.test_candidate(self.in_str, self.ad, self.off_dst)
                    self.ad +=1
                    if off:
                        #print 'found', hex(off)
                        return off
            self.class_index+=1
            self.ad = 0
        raise StopIteration
    def __iter__(self):
        return self
