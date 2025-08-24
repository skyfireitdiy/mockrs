    .text
    .global callee_ret_7
    .type callee_ret_7, %function
callee_ret_7:
    mov x0, #7
    ret

    .global bl_first_bl
    .type bl_first_bl, %function
bl_first_bl:
    bl callee_ret_7         // 首条为 BL，被蹦床按绝对调用并带回跳处理
    add x0, x0, #3
    ret
