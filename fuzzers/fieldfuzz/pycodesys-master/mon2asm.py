#! /usr/bin/env python2
OPCODES_MON2 = [('Cmd_Halt',0,0), ('Cmd_Ld16',2,0), ('Cmd_Ld32',4,0), ('Cmd_Cpy',0,3), ('Cmd_Es',1,1), ('Cmd_Rao',1,1), ('Cmd_Rst',1,3), ('Cmd_Nop',0,1), ('Cmd_Der',1,1), ('Cmd_Bit',0,2), ('Cmd_SetBit',1,3), ('Cmd_Arr',0,5), ('Cmd_Dup',0,1), ('Cmd_Add',0,2), ('Cmd_Sub',0,2), ('Cmd_MulS',0,2), ('Cmd_DivS',0,2), ('Cmd_ModS',0,2), ('Cmd_And',0,2), ('Cmd_Fld',1,1), ('Cmd_FAlloc',2,0), ('Cmd_FAddrE',0,0), ('Cmd_FAddrB',1,0), ('Cmd_Call',5,1), ('Cmd_Itf',0,1), ('Cmd_VFTab',2,1), ('Cmd_Bnz',2,1), ('Cmd_Ld64',8,0), ('Cmd_Es64',1,2), ('Cmd_IoPR',0,6), ('Cmd_IoPW',0,6), ('Cmd_SetLE',0,0), ('Cmd_SetBE',0,0), ('Cmd_SetNZ',0,0), ('Cmd_SubR',0,2), ('Cmd_SubLR',0,4), ('Cmd_CRToLR',0,1), ('Cmd_CLRToR',0,2), ('Cmd_CIntToR',1,1), ('Cmd_CIntToLR',1,1), ('Cmd_CRToInt',1,1), ('Cmd_CLRToInt',1,2), ('Cmd_Nop',0,2), ('Cmd_Sub64',0,4), ('Cmd_C64To32',0,2), ('Cmd_C32To64',0,1), ('Cmd_CIntToR64',1,2), ('Cmd_CIntToLR64',1,2), ('Cmd_CRToInt64',1,1), ('Cmd_CLRToInt64',1,2), ('Cmd_Der64',1,1), ('Cmd_Fld64',1,2), ('Cmd_Add64',0,4), ('Cmd_AddR',0,2), ('Cmd_AddLR',0,4), ('Cmd_AdrLit',2,0), ('Cmd_InvOpc',0,0)]


bytecode1 = "\x02\xBE\xEF\x06\x00"
# Magic sequences (IDE x32 3.5 SP16, Runtime: sutd 32):
unknown_1 = "\x1b\x00\x15\x0c"
unknown_2 = "\x17\x0c\x09\x04" + "\x1b\x06\x00\x01"
unknown_3 = "\x17\x04\x09\x04" + "\x17\x08\x09\x04" + "\x04\x00"



def print_disasm(bytecode):

    print('\n*** Program: %s' % bytecode.encode('hex'))
    print('*** Length: %d' % len(bytecode))
    print('\n')

    pos = 0
    while pos<len(bytecode):
        num_b = int(bytecode[pos].encode('hex'), 16)
        cmd_name, cmd_args, cmd_inputs  = OPCODES_MON2[num_b-1]
        print("*|* 0x%s *|* %s (%s args, %s inputs)" % (bytecode[pos].encode('hex'), cmd_name, cmd_args, cmd_inputs))
        if cmd_args>0:
            # Process args
            for i in range(0,cmd_args):
                print('Arg %d: %s' % (i+1, bytecode[pos+i+1].encode('hex')))
            # Jump to next instr
            pos += cmd_args

        pos+=1


print('\n*** Mon2 disassm')

print_disasm(bytecode1)
#print_disasm(unknown_2)
#print_disasm(unknown_3)

print('\nDone\n')
