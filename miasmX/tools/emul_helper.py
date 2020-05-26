#!/usr/bin/env python
#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
# Modifications (C) 2011-2020 Airbus, Louis.Granboulan@airbus.com
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
from miasmX.expression.expression_eval_abstract import *

log_emu_helper = logging.getLogger("emu.helper")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_emu_helper.addHandler(console_handler)
log_emu_helper.setLevel(logging.WARN)

jcc = ['jz', 'je', 'jne', 'jnz', 'jp', 'jnp', 'jg', 'jge', 'ja', 'jae', 'jb', 'jbe', 'jnb', 'jc', 'jnc', 'jl', 'jle', 'js', 'jns', 'jo', 'jno', 'loop', 'loopne', 'loope', 'jecxz']

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
