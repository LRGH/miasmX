#!/usr/bin/env python
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

from miasmX.arch.ia32_sem import *
from miasmX.expression.expression_helper import *
from miasmX.core.memory_pool import *

from miasmX.expression.expression_eval_abstract import *

log_emu_helper = logging.getLogger("emu.helper")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_emu_helper.addHandler(console_handler)
log_emu_helper.setLevel(logging.WARN)

def hexdump(a, offset = 0):
    out =""
    for i,c in enumerate(a):
        if i%0x10==0:
            out+="\n%.8X "%(offset+i)

        out+="%.2X "%ord(c)
    return out


def tohex(a):

    try:
        a = int(a)
    except ValueError:
        return a
    if a <0:
        a = struct.pack('l', a)
    else:
        a = struct.pack('L', a)
    a = struct.unpack('L', a)[0]
    return hex(a)


jcc = ['jz', 'je', 'jne', 'jnz', 'jp', 'jnp', 'jg', 'jge', 'ja', 'jae', 'jb', 'jbe', 'jnb', 'jc', 'jnc', 'jl', 'jle', 'js', 'jns', 'jo', 'jno', 'loop', 'loopne', 'loope', 'jecxz']

def dump_pool(p):
    log_emu_helper.error('/-------------\\')
    for x in p:
        log_emu_helper.error('%s %s', x, tohex(str(p[x])))
    log_emu_helper.error('\\_____________/')

def dump_reg(p):
    out = " "*20
    for x in [eax, ebx, ecx, edx, esi, edi, esp, ebp, zf]:
        if isinstance(p[x], ExprInt):
            out+=str(x)+' %.8X  '%int(p[x].arg)
        else:
            out+=str(x)+' %s  '%p[x]

    return out

def cmp_ptr(x, y):
    r = expr_simp(x.arg-y.arg)
    if not isinstance(r, ExprInt):
        return 1
    if r.arg == 0:
        return 0
    r = expr_simp(get_op_msb(r))
    if r == ExprInt(uint1(0)):
        return 1
    else:
        return -1
def dump_mem(p):
    out = []
    todo = []
    kk = p.keys()
    kk.sort()
    for x in kk:
        if isinstance(x, ExprMem):
            todo.append(x)
    todo.sort(cmp=lambda x,y:cmp_ptr(x, y))
    for x in todo:
        out.append('%s    %s'%(str(x), str(p[x])))

    return "\n".join(out)

def mem_read(evaluator, env, src_address, mem_size):
    if not isinstance(src_address, ExprInt):
        dump_pool(evaluator.pool)
        raise ValueError("cannot read %s"%src_address)
    src_address_l = int(src_address.arg)
    try:

        if mem_size == 32:
            ret = uint32(env.get_d(src_address_l))
        elif mem_size == 16:
            ret = uint16(env.get_w(src_address_l))
        elif mem_size == 8:
            ret = uint8(env.get_b(src_address_l))
        else:
            raise ValueError('unknown size read %s'%src_address.nbytes)
        log_emu_helper.debug("=>read @(%X)(%.8X)", src_address_l, int(ret))
        return ExprInt(ret)
    except ValueError:
        dump_pool(evaluator.pool)
        raise ValueError('read bug at 0x%X'%int(src_address_l))

def mem_write(evaluator, env, mem_size, dst_address, src_val, pool_out = None):
    if not isinstance(dst_address, ExprInt) or not isinstance(src_val, ExprInt):
        dump_pool(evaluator.pool)
        raise ValueError("cannot write %s %s"%(str(dst_address), str(src_val)))
    dst_address_l = int(dst_address.arg)
    src_val = src_val.arg
    try:
        log_emu_helper.debug("=>write @(%X)(%.8X)", dst_address_l, int(src_val))
        if mem_size == 32:
            env.set_d(dst_address_l, src_val&0xffffffff)
        elif mem_size == 16:
            env.set_w(dst_address_l, src_val&0xffff)
        elif mem_size == 8:
            env.set_b(dst_address_l, src_val&0xff)
        else:
            raise ValueError('unknown size write %s'%dst_address.nbytes)
    except ValueError:
        dump_pool(evaluator.pool)
        raise' write bug'
"""
###XXX for eval int
def get_instr_expr_args(name, modifs, mnemo_mode, args, my_eip):
    for a in args:
        if type(a) == int:
            raise ValueError('int deprec in args')


    if name in ['jmp']:
        if isinstance(args[0], ExprInt):
            print("%s %s"%("X"*0x10, args[0]))
            arga = args[0].arg
            if isinstance(arga, uint8):
                arga = int8(arga)
            e = mnemo_func[name](ExprOp('+', my_eip, ExprInt(uint32(arga))))
        else:
            e = mnemo_func[name](*args)
    elif name in jcc:
        arga = args[0].arg
        if isinstance(arga, uint8):
            arga = int8(arga)
        e = mnemo_func[name](my_eip, ExprOp('+', my_eip, ExprInt(uint32(arga))))
    elif name in ['call']:
        if isinstance(args[0], ExprInt):# or is_imm(args[0]):
            arga = args[0].arg
            if isinstance(arga, uint8):
                arga = int8(arga)

            e = mnemo_func[name](my_eip, ExprOp('+', my_eip, ExprInt(uint32(arga))))
        else:
            e = mnemo_func[name](my_eip, args[0])
    else:
        e = mnemo_func[name](*args)
    return e
"""


###XXX for eval abs
def get_instr_expr_args(l, args, my_eip):
    for a in args:
        if type(a) == int:
            raise ValueError('int deprec in args')

    info = l
    if l.m.name in ['jmp']:
        if isinstance(args[0], ExprInt):
            e = mnemo_func[l.m.name](info, args[0])
        else:
            e = mnemo_func[l.m.name](info, *args)
    elif l.m.name in jcc:
        e = mnemo_func[l.m.name](l, my_eip, args[0])
    elif l.m.name in ['call']:
        e = mnemo_func[l.m.name](l, my_eip, args[0])
    elif l.m.name in mnemo_func:
        e = mnemo_func[l.m.name](l, *args)
    elif '#' in l.m.name:
        # Most MMX/SSE instructions leave eflags untouched
        e = MMXnoflags(l, *args)
    else:
        # Raises an error
        e = mnemo_func[l.m.name](l, *args)
    return e

###XXX for eval abs
def get_instr_expr(l, my_eip, args = None, segm_to_do = set()):
    if args==None:args = []
    for x in l.arg:
        args.append(dict_to_Expr(x, l.m.modifs, l.opmode, l.admode, segm_to_do))
    l.arg_expr = args
    return get_instr_expr_args(l, args, my_eip)





def emul_expr(machine, e, my_eip):
    mem_dst = machine.eval_instr(e)

    if eip in machine.pool:
        if isinstance(machine.pool[eip], ExprCond):
            pass
        my_eip = machine.eval_expr(eip, {})
        del machine.pool[eip]
    return my_eip, mem_dst

def emul_bloc(machine, bloc):
    return emul_lines(machine, bloc.lines)



def emul_lines(machine, lines):
    my_eip = None
    for l in lines:
        my_eip = ExprInt(uint32(l.offset))

        args = []
        my_eip.arg+=uint32(l.l)
        ex = get_instr_expr(l, my_eip, args)
        my_eip, mem_dst = emul_full_expr(ex, l, my_eip, None, machine)

        for k in machine.pool:
            machine.pool[k] = expr_simp(machine.pool[k])

    return my_eip



def emul_imp_init(machine, libbase = 0xCCC00000, malloc_next_ad = 0xEEE00000):
    #for loadlibrary & getprocaddress emul
    machine.lib_bases = {}
    machine.lib_bases_func_index = {}
    machine.lib_base = libbase
    machine.func_loaded = {}

    #for malloc & free emul
    machine.malloc_next_ad = malloc_next_ad;


def emul_loadlibrary(machine, env):
    my_esp = machine.eval_expr(machine.pool[esp], {})
    libname_ad = env.get_d(my_esp+4)
    libname = ""
    l = 0
    while True:
        libname+=chr(env.get_b(libname_ad+l))
        l+=1
        if libname[-1]=='\x00':
            break

    machine.lib_bases[machine.lib_base] = libname
    machine.lib_bases_func_index[machine.lib_base] = machine.lib_base+1
    machine.eval_instr(mov(eax, ExprInt(uint32(machine.lib_base))))

    machine.lib_base+=0x1000
    print("emul loadlib %X, %s"%(libname_ad, libname[:-1]))
    log.info("emul loadlib %X, %s"%(libname_ad, libname))
    machine.eval_instr(ret(ExprInt(uint32(4))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    return my_eip

def emul_getprocaddress(machine, env):
    my_esp = machine.eval_expr(machine.pool[esp], {})
    libbase_ad = env.get_d(my_esp+4)
    funcname_ad = env.get_d(my_esp+8)
    funcname = ""
    l = 0
    while True:
        funcname+=chr(env.get_b(funcname_ad+l))
        l+=1
        if funcname[-1]=='\x00':
            break

    log.info("emul getprocaddress %X, %s"%(libbase_ad, funcname))
    print("emul getprocaddress %X, %s"%(libbase_ad, funcname[:-1]))

    if not libbase_ad in machine.lib_bases:
        log.debug(machine.lib_bases)
        raise 'unknown base lib! %s'%str(libbase_ad)
    func_ad = machine.lib_bases_func_index[libbase_ad]

    machine.lib_bases_func_index[libbase_ad]+=1
    machine.eval_instr(mov(eax, ExprInt(uint32(func_ad))))

    machine.func_loaded[func_ad] = funcname

    machine.eval_instr(ret(ExprInt(uint32(8))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    return my_eip

def hook_import_func(env, imported_func, start_address_hook = 0xAABB0000):
    func_hook_ptr = {}
    for f in imported_func:
        env.set_d(f, start_address_hook)
        func_hook_ptr[start_address_hook] = imported_func[f]
        start_address_hook+=0x10000

    return func_hook_ptr

def dump_imp(machine):

     log_emu_helper.warn('_'*10)
     for l in machine.lib_bases:
         log_emu_helper.warn("%.8X %s", l, machine.lib_bases[l])

     log_emu_helper.warn('_'*10)
     for f in machine.func_loaded:
         log_emu_helper.warn("%.8X %s", f, machine.func_loaded[f])


def emul_malloc(machine, env):
    my_esp = machine.get_reg(esp)
    pool_type =env.get_d(my_esp+0x4)
    alloc_size =env.get_d(my_esp+0x8)
    tag =env.get_d(my_esp+0xc)

    machine.eval_instr(ret(ExprInt(uint32(0xc))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]

    ret_alloc_ad = machine.malloc_next_ad
    m_data = mempool(machine.malloc_next_ad, machine.malloc_next_ad+alloc_size, 'RW', name = "malloc %.8X"%alloc_size)
    machine.malloc_next_ad += ((alloc_size+0xFFF)&(~0xFFF))

    log.warn('alloc(%X) tag %X poolt %X from %X esp %X ret %X:'%(int(alloc_size), int(tag), int(pool_type), int(my_eip), int(my_esp), int(machine.malloc_next_ad)))
    machine.eval_instr(mov(eax, ExprInt(uint32(ret_alloc_ad))))

    env.mems.append(m_data)
    log.warn(str(env))
    return my_eip

def emul_free(machine, env):
    my_esp = machine.get_reg(esp)
    address_free =env.get_d(my_esp+4)

    machine.eval_instr(ret(ExprInt(uint32(4))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]

    log.warn('free(%X) from %X esp %X:'%(int(address_free), int(my_eip), int(my_esp)))

    if address_free !=0:
        m = env.get_mem_pool(address_free)
        if not m:
            raise 'cannot find freeing mem!'
        env.mems.remove(m)
    log.warn(str(env))
    return my_eip


def emul_pitfall(machine, env):
    raise 'func not impl!'


def emul_heapcreate(machine, env):
    my_esp = machine.get_reg(esp)
    floptions =env.get_d(my_esp+4)
    dwinitialsize =env.get_d(my_esp+8)
    dwmaximumsize =env.get_d(my_esp+12)

    machine.eval_instr(ret(ExprInt(uint32(12))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]


    log.warn('heapcreate(%X %X %X) from %X esp %X ret %X:'%(floptions, dwinitialsize, dwmaximumsize, int(my_eip), my_esp, 0xdeadcafe))
    machine.eval_instr(mov(eax, ExprInt(uint32(0xdeadcafe))))

    return my_eip

def emul_heapalloc(machine, env):
    my_esp = machine.get_reg(esp)
    hheap =env.get_d(my_esp+4)
    dwflags =env.get_d(my_esp+8)
    alloc_size =env.get_d(my_esp+12)

    machine.eval_instr(ret(ExprInt(uint32(12))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]

    ret_alloc_ad = machine.malloc_next_ad
    m_data = mempool(machine.malloc_next_ad, machine.malloc_next_ad+alloc_size, 'RW', name = "heapalloc %.8X"%alloc_size)
    machine.malloc_next_ad += ((alloc_size+0xFFF)&(~0xFFF))

    log.warn('heapalloc(%X %X %X) from %X esp %X ret %X:'%(hheap, dwflags, alloc_size, int(my_eip), my_esp, machine.malloc_next_ad))
    machine.eval_instr(mov(eax, ExprInt(uint32(ret_alloc_ad))))

    env.mems.append(m_data)
    log.warn(str(env))
    return my_eip

#VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
def emul_virtualprotect(machine, env):
    my_esp = machine.eval_expr(machine.pool[esp], {})
    lpaddress = env.get_d(my_esp+4)
    dwsize = env.get_d(my_esp+8)
    flnewprotect = env.get_d(my_esp+12)
    lpfloldprotect = env.get_d(my_esp+16)

    #XXX return 1??
    machine.eval_instr(mov(eax, ExprInt(uint32(1))))

    log.info("emul virtualprotect %X, %X %X %X"%(lpaddress, dwsize, flnewprotect, lpfloldprotect))
    machine.eval_instr(ret(ExprInt(uint32(16))))
    #dump_pool(machine.pool)
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    return my_eip

def emul_virtualalloc(machine, env):
    my_esp = machine.get_reg(esp)
    lpaddress =env.get_d(my_esp+4)
    alloc_size =env.get_d(my_esp+8)
    flallocationtype =env.get_d(my_esp+12)
    flprotect =env.get_d(my_esp+16)

    machine.eval_instr(ret(ExprInt(uint32(16))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]

    ret_alloc_ad = machine.malloc_next_ad
    m_data = mempool(machine.malloc_next_ad, machine.malloc_next_ad+alloc_size, 'RW', name = "virtualalloc %.8X"%alloc_size)
    machine.malloc_next_ad += ((alloc_size+0xFFF)&(~0xFFF))

    log.warn('virtualalloc(%X %X %X %X) from %X esp %X ret %X:'%(lpaddress, alloc_size, flallocationtype, flprotect, int(my_eip), my_esp, machine.malloc_next_ad))
    machine.eval_instr(mov(eax, ExprInt(uint32(ret_alloc_ad))))

    env.mems.append(m_data)
    log.warn(str(env))
    return my_eip


def emul_virtualfree(machine, env):
    my_esp = machine.get_reg(esp)
    address_free =env.get_d(my_esp+4)
    dwsize =env.get_d(my_esp+8)
    dwfreetype =env.get_d(my_esp+12)



    machine.eval_instr(ret(ExprInt(uint32(12))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]

    log.warn('virtualfree(%X %X %X) from %X esp %X:'%(address_free, dwsize, swfreetype, int(my_eip), my_esp))

    if address_free !=0:
        m = env.get_mem_pool(address_free)
        if not m:
            raise 'cannot find freeing mem!'
        env.mems.remove(m)
    log.warn(str(env))
    return my_eip



def emul_getmodulehandlea(machine, env):
    my_esp = machine.eval_expr(machine.pool[esp], {})
    libname_ad = env.get_d(my_esp+4)
    libname = ""
    l = 0
    while True:
        libname+=chr(env.get_b(libname_ad+l))
        l+=1
        if libname[-1]=='\x00':
            break


    machine.eval_instr(ret(ExprInt(uint32(4))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]


    log.info("emul loadlib (%X), %s from %X"%(libname_ad, libname, my_eip))

    if False:#libname.startswith("kernel32.dll"):
        machine.eval_instr(mov(eax, ExprInt(uint32(0x7C800000))))
    else:
        machine.eval_instr(mov(eax, ExprInt(uint32(0x0))))
        log.warn("unknown lib: %s"%str(libname))

    log.warn(str(env))

    return my_eip

def emul_kddisabledebugger(machine, env):
    my_esp = machine.get_reg(esp)

    machine.eval_instr(ret())
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]


    log.warn('emul_kddisabledebugger from %X esp %X '%(int(my_eip), int(my_esp)))
    machine.eval_instr(mov(eax, ExprInt(uint32(0))))

    log.warn(str(env))
    return my_eip



def sav_machine(machine, env, my_eip, snap_fmt_name):

    import StringIO, zlib
    print('SAVE**************tsc: %.10d***************'%machine.pool[tsc1].arg)
    machine.pool[eip] = my_eip
    env_s = StringIO.StringIO()
    env.to_file(env_s)
    env_s.flush()
    fname = snap_fmt_name+".env"
    open(fname%(machine.pool[tsc1].arg), 'wb').write(zlib.compress(env_s.getvalue(), 9))
    machine_s = StringIO.StringIO()
    machine.to_file(machine_s)
    machine_s.flush()
    fname = snap_fmt_name+".machine"
    open(fname%(machine.pool[tsc1].arg), 'wb').write(zlib.compress(machine_s.getvalue(), 9))
    del machine.pool[eip]


def load_machine(snap_fmt_name, step):

    import StringIO, zlib
    fname = snap_fmt_name+".env"
    env_s = StringIO.StringIO(zlib.decompress(open(fname%step, 'rb').read()))
    env = mempool_manager.from_file(env_s)
    fname = snap_fmt_name+".machine"
    machine_s = StringIO.StringIO(zlib.decompress(open(fname%step, 'rb').read()))
    machine = eval_int.from_file(machine_s, globals())
    my_eip = machine.pool[eip]
    del machine.pool[eip]
    print('LOAD**************tsc: %.10X***************'%machine.pool[tsc1].arg)
    print("machine eip: %.8X"%int(my_eip.arg))

    return machine, env, my_eip

def emul_full_expr(e, l, my_eip, env, machine):
    if ((not 0xF2 in l.prefix) and (not 0xF3 in l.prefix)) or \
           "MMX" in l.m.name or \
           not l.m.name[:-1] in ["ins", "outs", "movs", "lods", "stos", "cmps", "scas"]:
        my_eip, mem_dst = emul_expr(machine, e, my_eip)
    else:
        #rep mnemo
        #XXX HACK 16 bit
        tsc_inc = 0
        if 0x66 in l.prefix and l.m.name[-1]== "d":
            raise "not impl 16 bit string"
        if l.m.name[:-1] in ["cmps", "scas"]: # repz or repnz
            zf_w = False
            for x in e:
                if zf in x.get_w():
                    zf_w = True
        else: # rep
            zf_w = False

        def expr_depth(f):
            if isinstance(f, ExprOp) or isinstance(f, ExprCompose):
                depth = 1
                for a in f.args:
                    depth += expr_depth(a)
                return depth
            elif isinstance(f, ExprMem):
                return 1 + expr_depth(f.arg)
            elif isinstance(f, ExprCond):
                return expr_depth(f.cond)+expr_depth(f.src1)+expr_depth(f.src2)
            else:
                return 0

        while True:

            my_ecx = machine.eval_expr(machine.pool[ecx], {})
            if not isinstance(my_ecx, ExprInt):
                raise ValueError('Emulation fails for "%s". ECX value is %s'
                    % (l, str(machine.pool[ecx])))
            if l.mnemo_mode== u16:
                my_ecx.arg&=0xFFFF
            if my_ecx.arg ==0:
                break

            my_esi = machine.eval_expr(machine.pool[esi], {})
            my_edi = machine.eval_expr(machine.pool[edi], {})
            if expr_depth(my_edi) > 100:
                raise ValueError('Emulation fails for "%s". EDI value is too complicated' % l)
            tmp,mem_dst =  emul_expr(machine, e, my_eip)
            if my_ecx.arg > 0x1000:
                # This is not a valid emulation, but we don't want to loop forever
                break

            info = l.opmode, l.admode
            machine.eval_instr(mov(info, ecx, ExprOp('-', my_ecx, ExprInt(uint32(1)))))
            machine.eval_expr(machine.pool[ecx], {})

            if zf_w :
                my_zf = machine.eval_expr(machine.pool[zf], {})
                if 0xF3 in l.prefix and my_zf == 0:
                    break
                if 0xF2 in l.prefix and my_zf == 1:
                    break

            tsc_inc += 1
        # serpillere included an emulation of TSC incrementation,
        # why here and nowhere else?
        if isinstance(machine.pool[tsc1], ExprInt):
            machine.pool[tsc1].arg += tsc_inc

    return my_eip, mem_dst


def guess_func_destack(all_bloc):
    ret_destack = None
    for b in all_bloc:
        l = b.lines[-1]
        if not l.m.name.startswith('ret'):
            continue
        if len(l.arg) == 0:
            a = 0
        elif len(l.arg) ==1:
            a = l.arg[0][x86_afs.imm]
        else:
            continue
        if ret_destack!=None:
            if a != ret_destack:
                print('found diff ret unstack %s %s'%(ret_destack, a))
                return None, None
            else:
                continue
        ret_destack = a


    if ret_destack !=None:
        return True, ret_destack

    #try func wrapper
    if len(all_bloc)!= 1:
        return None, None
    l = all_bloc[0].lines[-1]
    if not l.m.name.startswith('jmp') or len(l.arg) !=1:
        return None, None

    a = l.arg[0]
    print("%s %s %s"%(hex(l.offset), a, type(a)))

    if not x86_afs.imm in a or not x86_afs.ad in a or not a[x86_afs.ad]:
        return None, None

    return False, a[x86_afs.imm]


def digest_allbloc_instr(all_bloc, segm_to_do = set()):
    instrs = {}

    #test duplicated blocs
    unik_blobs = {}
    for b in all_bloc:
        if not b.label in unik_blobs:
            unik_blobs[b.label] = []
        unik_blobs[b.label].append(b)

    for lbl, blcs in unik_blobs.items():
        if len(blcs) ==1:
            continue
        tmp = blcs.pop()
        for b in blcs:
            if str(tmp) != str(b):
                print("%s != %s"%(tmp,b))
                raise ValueError('diff bloc in same label')
            all_bloc.remove(b)

    for b in all_bloc:
        for l in b.lines:
            if l.offset in instrs:
                log.warn(('zarb: dup instr', (hex(l.offset), str(l))))
                if str(instrs[l.offset][0]) != str(l):
                    raise ValueError('dup instr@ with different instr', (str(l), str(instrs[l.offset][0])))
            args = []
            ex = get_instr_expr(l, ExprInt(uint32(l.offset+l.l)), args, segm_to_do = segm_to_do)


            instrs[l.offset] = (l, ex)
    return instrs


def x86_machine(mem_read_wrap = None, mem_write_wrap = None):
    init_reg_new = init_regs.copy()
    init_reg_new.update({
        cs:ExprInt(uint32(9)),
        dr7:ExprInt(uint32(0)),
        cr0:init_cr0,
        #my_ret_addr:my_ret_addri
        })
    machine = eval_abs(init_reg_new,
                       mem_read_wrap,
                       mem_write_wrap,
                       )
    return machine

