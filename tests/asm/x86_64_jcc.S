    .text
    .globl jcc_first_je
    .type jcc_first_je, @function
jcc_first_je:
    je 1f                # 首条为条件跳转（依赖调用方设置的ZF）
    mov $3, %rax
    ret
1:
    mov $7, %rax
    ret

    .globl jcc_call_with_zf1
    .type jcc_call_with_zf1, @function
jcc_call_with_zf1:
    xor %eax, %eax
    test %eax, %eax      # 置 ZF=1
    call jcc_first_je
    ret

    .globl jcc_call_with_zf0
    .type jcc_call_with_zf0, @function
jcc_call_with_zf0:
    mov $1, %eax
    test %eax, %eax      # 置 ZF=0
    call jcc_first_je
    ret
