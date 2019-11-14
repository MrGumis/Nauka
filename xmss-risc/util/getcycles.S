.text

.globl getcycles
.align 2
getcycles:
    csrr a1, cycle
    csrr a0, cycle
    csrr a2, cycle
    bne a1, a2, getcycles
    ret
.size getcycles,.-getcycles
