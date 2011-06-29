.text
.p2align 5

curve25519_mul_sse2:
 pushl %ebp
 movl %esp, %ebp
 subl $488, %esp
 movdqa 16(%ecx), %xmm1
 pshufd $165, 16(%ecx), %xmm4
 pshufd $216, 32(%ecx), %xmm0
 psrldq $12, %xmm1
 movdqa %xmm4, -440(%ebp)
 pshufd $250, 16(%ecx), %xmm4
 movdqa %xmm0, -392(%ebp)
 movhpd 32(%ecx), %xmm1
 pshufd $250, %xmm0, %xmm7
 movdqa curve25519topmask_sse2, %xmm0
 movdqa %xmm4, -424(%ebp)
 movdqa %xmm1, -408(%ebp)
 movdqa %xmm0, %xmm1
 pshufd $85, (%edx), %xmm4
 pand %xmm4, %xmm1
 pshufd $170, (%edx), %xmm6
 movdqa %xmm7, -376(%ebp)
 movdqa %xmm0, %xmm7
 paddq %xmm1, %xmm4
 pshufd $255, (%edx), %xmm1
 movdqa %xmm6, -344(%ebp)
 pand %xmm1, %xmm7
 pshufd $0, (%edx), %xmm6
 movdqa %xmm6, -312(%ebp)
 paddq %xmm7, %xmm1
 pshufd $85, 16(%edx), %xmm6
 movdqa %xmm0, %xmm7
 pand %xmm6, %xmm7
 paddq %xmm7, %xmm6
 pshufd $170, 16(%edx), %xmm7
 movdqa %xmm7, -280(%ebp)
 movdqa %xmm6, -296(%ebp)
 movdqa %xmm0, %xmm6
 pshufd $255, 16(%edx), %xmm7
 pand %xmm7, %xmm6
 paddq %xmm6, %xmm7
 movdqa %xmm7, -264(%ebp)
 pshufd $221, 32(%edx), %xmm7
 pand %xmm7, %xmm0
 pshufd $0, 16(%edx), %xmm6
 paddq %xmm0, %xmm7
 pshufd $204, 32(%edx), %xmm0
 pshufd $216, (%ecx), %xmm2
 pshufd $250, (%ecx), %xmm3
 movdqa %xmm6, -248(%ebp)
 movdqa %xmm1, %xmm6
 movdqa %xmm0, -216(%ebp)
 movdqa %xmm4, %xmm0
 movdqa %xmm7, -232(%ebp)
 movdqa %xmm4, %xmm7
 pmuludq %xmm3, %xmm0
 pmuludq %xmm2, %xmm6
 pmuludq %xmm2, %xmm7
 paddq %xmm6, %xmm0
 movd 12(%ecx), %xmm5
 movdqa %xmm4, %xmm6
 movhpd 16(%ecx), %xmm5
 movdqa %xmm5, -472(%ebp)
 pshufd $216, 16(%ecx), %xmm5
 movdqa %xmm7, -200(%ebp)
 movdqa %xmm1, %xmm7
 pmuludq %xmm5, %xmm6
 pmuludq %xmm3, %xmm7
 paddq %xmm7, %xmm6
 movdqa -296(%ebp), %xmm7
 movdqa %xmm0, -184(%ebp)
 movdqa %xmm7, %xmm0
 pmuludq %xmm2, %xmm0
 paddq %xmm0, %xmm6
 movdqa %xmm6, -168(%ebp)
 movdqa %xmm4, %xmm0
 movdqa %xmm1, %xmm6
 pmuludq -424(%ebp), %xmm0
 pmuludq %xmm5, %xmm6
 movdqa %xmm5, -456(%ebp)
 movdqa %xmm7, %xmm5
 paddq %xmm6, %xmm0
 pmuludq %xmm3, %xmm5
 movdqa -264(%ebp), %xmm6
 movdqa %xmm3, -488(%ebp)
 movdqa %xmm6, %xmm3
 pmuludq %xmm2, %xmm3
 paddq %xmm5, %xmm0
 paddq %xmm3, %xmm0
 movdqa %xmm0, -152(%ebp)
 movdqa curve25519nineteen_sse2, %xmm0
 movdqa %xmm0, %xmm5
 movdqa %xmm0, %xmm3
 pmuludq -248(%ebp), %xmm5
 pmuludq -280(%ebp), %xmm3
 movdqa %xmm5, -136(%ebp)
 movdqa %xmm0, %xmm5
 pmuludq -216(%ebp), %xmm5
 movdqa %xmm5, -104(%ebp)
 movdqa %xmm1, -328(%ebp)
 movdqa %xmm3, -120(%ebp)
 pshufd $10, %xmm1, %xmm3
 pshufd $10, %xmm7, %xmm1
 pshufd $10, %xmm6, %xmm7
 pshufd $10, -232(%ebp), %xmm5
 pxor %xmm6, %xmm6
 pmuludq %xmm0, %xmm3
 pmuludq %xmm0, %xmm1
 pmuludq %xmm0, %xmm7
 pmuludq %xmm0, %xmm5
 movdqa -200(%ebp), %xmm0
 pslldq $8, %xmm0
 punpckhqdq %xmm0, %xmm6
 movdqa -312(%ebp), %xmm0
 pmuludq %xmm2, %xmm0
 paddq %xmm0, %xmm6
 pshufd $165, (%ecx), %xmm0
 pmuludq %xmm5, %xmm0
 movdqa %xmm7, -56(%ebp)
 paddq %xmm0, %xmm6
 movdqa %xmm7, %xmm0
 movdqa -472(%ebp), %xmm7
 pmuludq %xmm7, %xmm0
 pmuludq %xmm5, %xmm7
 paddq %xmm0, %xmm6
 movdqa %xmm1, -72(%ebp)
 pmuludq -440(%ebp), %xmm1
 movdqa %xmm3, -88(%ebp)
 pmuludq -408(%ebp), %xmm3
 paddq %xmm1, %xmm6
 movdqa %xmm4, -360(%ebp)
 paddq %xmm3, %xmm6
 pshufd $10, %xmm4, %xmm4
 movdqa curve25519nineteen_sse2, %xmm3
 pmuludq %xmm3, %xmm4
 pmuludq -376(%ebp), %xmm4
 paddq %xmm4, %xmm6
 movdqa -344(%ebp), %xmm4
 pmuludq %xmm4, %xmm3
 pmuludq -392(%ebp), %xmm3
 movdqa -104(%ebp), %xmm0
 paddq %xmm3, %xmm6
 movdqa -488(%ebp), %xmm3
 pmuludq %xmm3, %xmm0
 movdqa -120(%ebp), %xmm1
 pmuludq -456(%ebp), %xmm1
 paddq %xmm0, %xmm6
 movdqa -136(%ebp), %xmm0
 paddq %xmm1, %xmm6
 movdqa -424(%ebp), %xmm1
 pmuludq %xmm1, %xmm0
 paddq %xmm0, %xmm6
 movdqa %xmm6, %xmm0
 psrlq $26, %xmm0
 pslldq $8, %xmm0
 paddq %xmm0, %xmm6
 movdqa %xmm6, -24(%ebp)
 movdqa -184(%ebp), %xmm6
 movdqa -200(%ebp), %xmm0
 pslldq $8, %xmm6
 punpckhqdq %xmm6, %xmm0
 movdqa -312(%ebp), %xmm6
 pmuludq %xmm3, %xmm6
 paddq %xmm6, %xmm0
 movdqa %xmm4, %xmm6
 pmuludq %xmm2, %xmm6
 paddq %xmm6, %xmm0
 paddq %xmm7, %xmm0
 movdqa -56(%ebp), %xmm7
 pmuludq -440(%ebp), %xmm7
 movdqa -72(%ebp), %xmm6
 pmuludq -408(%ebp), %xmm6
 paddq %xmm7, %xmm0
 movdqa -88(%ebp), %xmm7
 pmuludq -376(%ebp), %xmm7
 paddq %xmm6, %xmm0
 movdqa -456(%ebp), %xmm6
 paddq %xmm7, %xmm0
 movdqa -104(%ebp), %xmm7
 pmuludq %xmm6, %xmm7
 paddq %xmm7, %xmm0
 movdqa -120(%ebp), %xmm7
 pmuludq %xmm1, %xmm7
 movdqa -136(%ebp), %xmm1
 paddq %xmm7, %xmm0
 movdqa -392(%ebp), %xmm7
 pmuludq %xmm7, %xmm1
 paddq %xmm1, %xmm0
 movdqa -24(%ebp), %xmm1
 psrlq $25, %xmm1
 psrldq $8, %xmm1
 paddq %xmm1, %xmm0
 movdqa %xmm0, %xmm1
 psrlq $26, %xmm1
 pslldq $8, %xmm1
 paddq %xmm1, %xmm0
 movdqa %xmm0, -200(%ebp)
 movdqa -168(%ebp), %xmm0
 movdqa -184(%ebp), %xmm1
 pslldq $8, %xmm0
 punpckhqdq %xmm0, %xmm1
 movdqa -312(%ebp), %xmm0
 pmuludq %xmm6, %xmm0
 paddq %xmm0, %xmm1
 movdqa -248(%ebp), %xmm0
 movdqa %xmm0, %xmm6
 pmuludq %xmm2, %xmm6
 pmuludq %xmm3, %xmm0
 paddq %xmm6, %xmm1
 movdqa %xmm4, %xmm6
 pmuludq %xmm3, %xmm6
 paddq %xmm6, %xmm1
 movdqa -440(%ebp), %xmm6
 pmuludq %xmm5, %xmm6
 movdqa %xmm5, -40(%ebp)
 movdqa -56(%ebp), %xmm5
 pmuludq -408(%ebp), %xmm5
 paddq %xmm6, %xmm1
 movdqa -72(%ebp), %xmm6
 pmuludq -376(%ebp), %xmm6
 paddq %xmm5, %xmm1
 movdqa -104(%ebp), %xmm5
 paddq %xmm6, %xmm1
 movdqa -424(%ebp), %xmm6
 pmuludq %xmm6, %xmm5
 paddq %xmm5, %xmm1
 movdqa -120(%ebp), %xmm5
 pmuludq %xmm7, %xmm5
 paddq %xmm5, %xmm1
 movdqa -200(%ebp), %xmm5
 psrlq $25, %xmm5
 psrldq $8, %xmm5
 paddq %xmm5, %xmm1
 movdqa %xmm1, %xmm5
 psrlq $26, %xmm5
 pslldq $8, %xmm5
 paddq %xmm5, %xmm1
 movdqa %xmm1, -184(%ebp)
 movdqa -152(%ebp), %xmm1
 movdqa -168(%ebp), %xmm5
 pslldq $8, %xmm1
 punpckhqdq %xmm1, %xmm5
 movdqa -312(%ebp), %xmm1
 pmuludq %xmm6, %xmm1
 paddq %xmm1, %xmm5
 paddq %xmm0, %xmm5
 movdqa -456(%ebp), %xmm0
 pmuludq %xmm0, %xmm4
 movdqa -280(%ebp), %xmm1
 pmuludq %xmm2, %xmm1
 paddq %xmm4, %xmm5
 movdqa -408(%ebp), %xmm4
 pmuludq -40(%ebp), %xmm4
 paddq %xmm1, %xmm5
 movdqa -56(%ebp), %xmm1
 paddq %xmm4, %xmm5
 movdqa -376(%ebp), %xmm4
 pmuludq %xmm4, %xmm1
 paddq %xmm1, %xmm5
 movdqa -104(%ebp), %xmm1
 pmuludq %xmm7, %xmm1
 paddq %xmm1, %xmm5
 movdqa -184(%ebp), %xmm1
 psrlq $25, %xmm1
 psrldq $8, %xmm1
 paddq %xmm1, %xmm5
 movdqa %xmm5, %xmm1
 psrlq $26, %xmm1
 pslldq $8, %xmm1
 paddq %xmm1, %xmm5
 movdqa %xmm5, -168(%ebp)
 movdqa -360(%ebp), %xmm1
 movdqa -328(%ebp), %xmm5
 pmuludq %xmm7, %xmm1
 pmuludq %xmm6, %xmm5
 paddq %xmm5, %xmm1
 movdqa -296(%ebp), %xmm5
 pmuludq %xmm0, %xmm5
 paddq %xmm5, %xmm1
 movdqa -264(%ebp), %xmm5
 pmuludq %xmm3, %xmm5
 paddq %xmm5, %xmm1
 movdqa -232(%ebp), %xmm5
 pmuludq %xmm2, %xmm5
 paddq %xmm5, %xmm1
 movdqa -152(%ebp), %xmm5
 pslldq $8, %xmm1
 punpckhqdq %xmm1, %xmm5
 movdqa -312(%ebp), %xmm1
 pmuludq %xmm7, %xmm1
 movdqa -216(%ebp), %xmm7
 pmuludq %xmm2, %xmm7
 paddq %xmm1, %xmm5
 movdqa -280(%ebp), %xmm2
 pmuludq %xmm3, %xmm2
 paddq %xmm7, %xmm5
 movdqa -248(%ebp), %xmm3
 pmuludq %xmm0, %xmm3
 paddq %xmm2, %xmm5
 movdqa -344(%ebp), %xmm1
 pmuludq %xmm6, %xmm1
 paddq %xmm3, %xmm5
 movdqa -40(%ebp), %xmm0
 pmuludq %xmm4, %xmm0
 paddq %xmm1, %xmm5
 movdqa -168(%ebp), %xmm1
 movdqa %xmm1, %xmm4
 psrlq $25, %xmm4
 paddq %xmm0, %xmm5
 psrldq $8, %xmm4
 paddq %xmm4, %xmm5
 movdqa %xmm5, %xmm7
 psrlq $26, %xmm7
 pslldq $8, %xmm7
 paddq %xmm7, %xmm5
 movdqa %xmm5, %xmm6
 psrlq $25, %xmm6
 psrldq $8, %xmm6
 movdqa curve25519nineteen_sse2, %xmm7
 pmuludq %xmm7, %xmm6
 movdqa curve25519mask2625_sse2, %xmm3
 movdqa -24(%ebp), %xmm0
 pand %xmm3, %xmm1
 pand %xmm3, %xmm0
 pand %xmm3, %xmm5
 paddq %xmm6, %xmm0
 movdqa %xmm0, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm0
 movdqa %xmm0, %xmm4
 pand %xmm3, %xmm0
 movdqa -200(%ebp), %xmm6
 psrlq $25, %xmm4
 psrldq $8, %xmm4
 pand %xmm3, %xmm6
 paddq %xmm4, %xmm6
 movdqa %xmm6, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm6
 movdqa %xmm6, %xmm2
 pand %xmm3, %xmm6
 movdqa -184(%ebp), %xmm4
 psrlq $25, %xmm2
 psrldq $8, %xmm2
 pand %xmm3, %xmm4
 paddq %xmm2, %xmm4
 movdqa %xmm4, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm4
 movdqa %xmm4, %xmm2
 pand %xmm3, %xmm4
 psrlq $25, %xmm2
 psrldq $8, %xmm2
 paddq %xmm2, %xmm1
 movdqa %xmm1, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm1
 movdqa %xmm1, %xmm2
 pand %xmm3, %xmm1
 psrlq $25, %xmm2
 psrldq $8, %xmm2
 paddq %xmm2, %xmm5
 movdqa %xmm5, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm5
 pshufd $143, %xmm6, %xmm2
 movdqa %xmm5, %xmm6
 psrlq $25, %xmm6
 pand %xmm3, %xmm5
 psrldq $8, %xmm6
 pmuludq %xmm7, %xmm6
 paddq %xmm6, %xmm0
 pshufd $248, %xmm0, %xmm0
 pshufd $143, %xmm1, %xmm7
 por %xmm0, %xmm2
 pshufd $248, %xmm4, %xmm1
 pshufd $248, %xmm5, %xmm3
 por %xmm1, %xmm7
 movdqa %xmm2, (%eax)
 movdqa %xmm7, 16(%eax)
 movdqa %xmm3, 32(%eax)
 movl %ebp, %esp
 popl %ebp
 ret



curve25519_square_times_sse2:
 subl $492, %esp
 movdqa curve25519bottommask_sse2, %xmm7
 movdqa curve25519topmask_sse2, %xmm6
 movdqa curve25519mask2625_sse2, %xmm4
 movdqa curve25519nineteen_sse2, %xmm2
 movdqa curve25519nineteen2x_sse2, %xmm0
 movdqa (%edx), %xmm1
 movdqa 16(%edx), %xmm5
 movdqa 32(%edx), %xmm3
 movdqa %xmm0, (%esp)
 movdqa %xmm2, 32(%esp)
 movdqa %xmm4, 64(%esp)
 movdqa %xmm6, 16(%esp)
 movdqa %xmm7, 48(%esp)
Lsquare_count:
 pshufd $165, %xmm1, %xmm7
 movdqa %xmm1, %xmm6
 pshufd $216, %xmm5, %xmm4
 decl %ecx
 movdqa %xmm7, 112(%esp)
 pshufd $250, %xmm1, %xmm7
 movdqa %xmm4, 160(%esp)
 pshufd $0, %xmm5, %xmm4
 movdqa %xmm7, 128(%esp)
 pshufd $165, %xmm5, %xmm7
 movdqa %xmm4, 208(%esp)
 movdqa %xmm7, 176(%esp)
 pshufd $170, %xmm5, %xmm7
 movdqa 32(%esp), %xmm4
 pmuludq %xmm4, %xmm7
 psrldq $12, %xmm6
 punpcklqdq %xmm5, %xmm6
 movdqa %xmm6, 144(%esp)
 pshufd $250, %xmm5, %xmm6
 movdqa %xmm6, 192(%esp)
 movdqa %xmm7, 224(%esp)
 pshufd $255, %xmm5, %xmm7
 movdqa (%esp), %xmm6
 pmuludq %xmm6, %xmm7
 movdqa %xmm7, 240(%esp)
 pshufd $0, %xmm3, %xmm7
 pmuludq %xmm4, %xmm7
 movdqa %xmm7, 272(%esp)
 pshufd $85, %xmm3, %xmm7
 movdqa %xmm5, 96(%esp)
 psrldq $12, %xmm5
 pmuludq %xmm6, %xmm7
 movdqa 16(%esp), %xmm6
 movdqa %xmm3, 80(%esp)
 pshufd $0, %xmm1, %xmm2
 punpcklqdq %xmm3, %xmm5
 movdqa %xmm6, %xmm3
 pand %xmm2, %xmm3
 pshufd $170, %xmm1, %xmm0
 paddq %xmm3, %xmm2
 pand %xmm0, %xmm6
 movdqa %xmm5, 256(%esp)
 pslld $1, %xmm5
 pshufd $230, %xmm2, %xmm3
 movdqa %xmm5, 416(%esp)
 movdqa %xmm3, 304(%esp)
 paddq %xmm6, %xmm0
 pshufd $85, %xmm1, %xmm3
 pshufd $255, %xmm1, %xmm6
 pslld $1, %xmm3
 pshufd $216, %xmm1, %xmm1
 pslld $1, %xmm6
 movdqa 112(%esp), %xmm5
 pmuludq %xmm2, %xmm1
 movdqa %xmm5, %xmm2
 pslld $1, %xmm2
 movdqa %xmm0, 320(%esp)
 pshufd $230, %xmm0, %xmm0
 movdqa %xmm0, 336(%esp)
 pmuludq %xmm7, %xmm2
 movdqa 48(%esp), %xmm0
 movdqa %xmm6, 368(%esp)
 movdqa %xmm0, %xmm6
 pand %xmm3, %xmm6
 movdqa %xmm3, 352(%esp)
 paddq %xmm3, %xmm6
 paddq %xmm2, %xmm1
 pmuludq 352(%esp), %xmm5
 movdqa 144(%esp), %xmm3
 movdqa 240(%esp), %xmm2
 pslld $1, %xmm3
 pmuludq %xmm3, %xmm2
 pmuludq %xmm7, %xmm3
 paddq %xmm2, %xmm1
 pshufd $85, 96(%esp), %xmm2
 pmuludq %xmm4, %xmm2
 movdqa %xmm6, 384(%esp)
 pand %xmm0, %xmm2
 movdqa 160(%esp), %xmm6
 pslld $1, %xmm6
 movdqa %xmm6, 400(%esp)
 movdqa 176(%esp), %xmm6
 movdqa 128(%esp), %xmm4
 pslld $1, %xmm6
 movdqa %xmm4, %xmm0
 pmuludq %xmm6, %xmm2
 pslld $1, %xmm0
 pmuludq 272(%esp), %xmm0
 paddq %xmm2, %xmm1
 movdqa 224(%esp), %xmm2
 paddq %xmm0, %xmm1
 movdqa 400(%esp), %xmm0
 pmuludq %xmm0, %xmm2
 pmuludq 272(%esp), %xmm0
 paddq %xmm2, %xmm1
 movdqa %xmm1, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm1
 movdqa 304(%esp), %xmm2
 pmuludq %xmm2, %xmm4
 paddq %xmm5, %xmm4
 movdqa 240(%esp), %xmm5
 paddq %xmm3, %xmm4
 movdqa %xmm5, %xmm3
 pmuludq %xmm6, %xmm3
 pmuludq %xmm7, %xmm6
 paddq %xmm3, %xmm4
 movdqa 48(%esp), %xmm3
 paddq %xmm0, %xmm4
 movdqa %xmm3, %xmm0
 pand 192(%esp), %xmm0
 pmuludq 224(%esp), %xmm0
 movdqa %xmm1, 432(%esp)
 psrlq $25, %xmm1
 paddq %xmm0, %xmm4
 psrldq $8, %xmm1
 paddq %xmm1, %xmm4
 movdqa 160(%esp), %xmm1
 movdqa %xmm4, %xmm0
 pmuludq %xmm2, %xmm1
 psrlq $26, %xmm0
 movdqa 128(%esp), %xmm2
 pmuludq 320(%esp), %xmm2
 pslldq $8, %xmm0
 paddq %xmm0, %xmm4
 paddq %xmm2, %xmm1
 movdqa 384(%esp), %xmm0
 movdqa 144(%esp), %xmm2
 pmuludq %xmm2, %xmm0
 paddq %xmm0, %xmm1
 paddq %xmm6, %xmm1
 pshufd $170, %xmm5, %xmm6
 movdqa 416(%esp), %xmm5
 pand %xmm3, %xmm6
 pmuludq %xmm5, %xmm6
 pmuludq %xmm7, %xmm5
 paddq %xmm6, %xmm1
 movdqa 192(%esp), %xmm6
 movdqa %xmm6, %xmm0
 movdqa 272(%esp), %xmm3
 pslld $1, %xmm0
 pmuludq %xmm3, %xmm0
 pmuludq 304(%esp), %xmm6
 paddq %xmm0, %xmm1
 movdqa %xmm4, 448(%esp)
 psrlq $25, %xmm4
 psrldq $8, %xmm4
 paddq %xmm4, %xmm1
 movdqa 160(%esp), %xmm4
 movdqa %xmm1, %xmm0
 pmuludq 336(%esp), %xmm4
 psrlq $26, %xmm0
 pslldq $8, %xmm0
 paddq %xmm0, %xmm1
 paddq %xmm4, %xmm6
 movdqa 176(%esp), %xmm0
 movdqa 384(%esp), %xmm4
 pmuludq %xmm4, %xmm0
 paddq %xmm0, %xmm6
 movdqa 368(%esp), %xmm0
 pmuludq %xmm0, %xmm2
 paddq %xmm2, %xmm6
 paddq %xmm5, %xmm6
 movdqa 80(%esp), %xmm5
 movdqa 48(%esp), %xmm2
 movdqa %xmm7, 288(%esp)
 movdqa %xmm5, %xmm7
 pand %xmm2, %xmm7
 pand %xmm0, %xmm2
 pmuludq %xmm3, %xmm7
 paddq %xmm2, %xmm0
 paddq %xmm7, %xmm6
 movdqa %xmm1, 464(%esp)
 psrlq $25, %xmm1
 psrldq $8, %xmm1
 paddq %xmm1, %xmm6
 pshufd $216, %xmm5, %xmm7
 movdqa %xmm6, %xmm3
 movdqa 192(%esp), %xmm1
 psrlq $26, %xmm3
 pmuludq 304(%esp), %xmm7
 pmuludq 336(%esp), %xmm1
 pslldq $8, %xmm3
 paddq %xmm3, %xmm6
 paddq %xmm1, %xmm7
 movdqa 16(%esp), %xmm1
 movdqa 208(%esp), %xmm3
 pand %xmm3, %xmm1
 paddq %xmm1, %xmm3
 movdqa 160(%esp), %xmm1
 pmuludq %xmm3, %xmm1
 movdqa 256(%esp), %xmm3
 pmuludq %xmm4, %xmm3
 paddq %xmm1, %xmm7
 paddq %xmm3, %xmm7
 movdqa 176(%esp), %xmm3
 movdqa %xmm6, %xmm1
 pmuludq %xmm0, %xmm3
 psrlq $25, %xmm1
 paddq %xmm3, %xmm7
 pshufd $253, %xmm5, %xmm3
 pshufd $170, 288(%esp), %xmm5
 pslld $1, %xmm3
 pmuludq %xmm5, %xmm3
 paddq %xmm3, %xmm7
 psrldq $8, %xmm1
 paddq %xmm1, %xmm7
 movdqa %xmm7, %xmm4
 psrlq $26, %xmm4
 pslldq $8, %xmm4
 paddq %xmm4, %xmm7
 movdqa %xmm7, %xmm1
 psrlq $25, %xmm1
 movdqa 32(%esp), %xmm0
 psrldq $8, %xmm1
 pmuludq %xmm0, %xmm1
 movdqa 64(%esp), %xmm3
 movdqa 432(%esp), %xmm5
 pand %xmm3, %xmm6
 pand %xmm3, %xmm5
 pand %xmm3, %xmm7
 paddq %xmm1, %xmm5
 movdqa %xmm5, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm5
 movdqa %xmm5, %xmm4
 pand %xmm3, %xmm5
 movdqa 448(%esp), %xmm1
 psrlq $25, %xmm4
 psrldq $8, %xmm4
 pand %xmm3, %xmm1
 paddq %xmm4, %xmm1
 movdqa %xmm1, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm1
 movdqa %xmm1, %xmm2
 pand %xmm3, %xmm1
 movdqa 464(%esp), %xmm4
 psrlq $25, %xmm2
 psrldq $8, %xmm2
 pand %xmm3, %xmm4
 paddq %xmm2, %xmm4
 movdqa %xmm4, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm4
 movdqa %xmm4, %xmm2
 pand %xmm3, %xmm4
 psrlq $25, %xmm2
 psrldq $8, %xmm2
 paddq %xmm2, %xmm6
 movdqa %xmm6, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm6
 movdqa %xmm6, %xmm2
 pand %xmm3, %xmm6
 psrlq $25, %xmm2
 psrldq $8, %xmm2
 paddq %xmm2, %xmm7
 movdqa %xmm7, %xmm2
 psrlq $26, %xmm2
 pslldq $8, %xmm2
 paddq %xmm2, %xmm7
 movdqa %xmm7, %xmm2
 pand %xmm3, %xmm7
 psrlq $25, %xmm2
 psrldq $8, %xmm2
 pmuludq %xmm0, %xmm2
 paddq %xmm2, %xmm5
 pshufd $143, %xmm1, %xmm1
 pshufd $248, %xmm5, %xmm5
 por %xmm5, %xmm1
 pshufd $143, %xmm6, %xmm5
 pshufd $248, %xmm4, %xmm6
 pshufd $248, %xmm7, %xmm3
 por %xmm6, %xmm5
 jne Lsquare_count
 movdqa %xmm3, 32(%eax)
 movdqa %xmm5, 16(%eax)
 movdqa %xmm1, (%eax)
 addl $492, %esp
 ret

curve25519_scalarmult_sse2:
 pushl %esi
 pushl %edi
 pushl %ebx
 pushl %ebp
 subl $972, %esp
 movl %ecx, %edi
 movaps curve25519one_sse2, %xmm0
 movaps %xmm0, 432(%esp)
 movaps 16+curve25519one_sse2, %xmm1
 movaps %xmm1, 448(%esp)
 movaps 32+curve25519one_sse2, %xmm2
 movaps %xmm2, 464(%esp)
 movaps curve25519one_sse2, %xmm0
 movaps %xmm0, 480(%esp)
 movaps 16+curve25519one_sse2, %xmm1
 movaps %xmm1, 496(%esp)
 movaps 32+curve25519one_sse2, %xmm2
 movaps %xmm2, 512(%esp)
 pxor %xmm0, %xmm0
 movaps %xmm0, 528(%esp)
 movaps %xmm0, 544(%esp)
 movaps %xmm0, 560(%esp)
 movl 992(%esp), %eax
 movdqa curve25519zeromodp0_sse2, %xmm6
 movdqa curve25519zeromodp1_sse2, %xmm5
 movzbl 1(%eax), %ecx
 shll $8, %ecx
 movzbl (%eax), %ebx
 orl %ecx, %ebx
 movzbl 2(%eax), %ecx
 shll $16, %ecx
 movzbl 3(%eax), %ebp
 orl %ecx, %ebx
 movl %ebp, %ecx
 shll $24, %ecx
 orl %ecx, %ebx
 andl $67108863, %ebx
 movl %ebx, 576(%esp)
 movzbl 4(%eax), %ebx
 shll $8, %ebx
 orl %ebx, %ebp
 movzbl 5(%eax), %ebx
 shll $16, %ebx
 movzbl 6(%eax), %ecx
 orl %ebx, %ebp
 movl %ecx, %ebx
 shll $24, %ebx
 orl %ebx, %ebp
 movzbl 7(%eax), %ebx
 shll $8, %ebx
 shrl $2, %ebp
 orl %ebx, %ecx
 movzbl 8(%eax), %ebx
 andl $33554431, %ebp
 shll $16, %ebx
 movl %ebp, 580(%esp)
 orl %ebx, %ecx
 movzbl 9(%eax), %ebp
 movl %ebp, %ebx
 shll $24, %ebx
 orl %ebx, %ecx
 movzbl 10(%eax), %ebx
 shll $8, %ebx
 shrl $3, %ecx
 orl %ebx, %ebp
 movzbl 11(%eax), %ebx
 andl $67108863, %ecx
 shll $16, %ebx
 movl %ecx, 584(%esp)
 orl %ebx, %ebp
 movzbl 12(%eax), %ecx
 movl %ecx, %ebx
 shll $24, %ebx
 orl %ebx, %ebp
 shrl $5, %ebp
 andl $33554431, %ebp
 movl %ebp, 588(%esp)
 movzbl 13(%eax), %ebp
 shll $8, %ebp
 movzbl 14(%eax), %ebx
 orl %ebp, %ecx
 shll $16, %ebx
 movzbl 15(%eax), %ebp
 orl %ebx, %ecx
 shll $24, %ebp
 orl %ebp, %ecx
 movzbl 17(%eax), %ebp
 shll $8, %ebp
 shrl $6, %ecx
 movl %ecx, 592(%esp)
 movzbl 16(%eax), %ecx
 orl %ebp, %ecx
 movzbl 18(%eax), %ebp
 shll $16, %ebp
 movzbl 19(%eax), %ebx
 orl %ebp, %ecx
 movl %ebx, %ebp
 shll $24, %ebp
 orl %ebp, %ecx
 andl $33554431, %ecx
 movl %ecx, 596(%esp)
 movzbl 20(%eax), %ecx
 shll $8, %ecx
 orl %ecx, %ebx
 movzbl 21(%eax), %ecx
 shll $16, %ecx
 movzbl 22(%eax), %ebp
 orl %ecx, %ebx
 movl %ebp, %ecx
 shll $24, %ecx
 orl %ecx, %ebx
 movzbl 23(%eax), %ecx
 shll $8, %ecx
 shrl $1, %ebx
 orl %ecx, %ebp
 movzbl 24(%eax), %ecx
 andl $67108863, %ebx
 shll $16, %ecx
 movl %ebx, 600(%esp)
 orl %ecx, %ebp
 movzbl 25(%eax), %ebx
 movl %ebx, %ecx
 shll $24, %ecx
 orl %ecx, %ebp
 shrl $3, %ebp
 andl $33554431, %ebp
 movl %ebp, 604(%esp)
 movzbl 26(%eax), %ebp
 shll $8, %ebp
 orl %ebp, %ebx
 movzbl 27(%eax), %ebp
 shll $16, %ebp
 movzbl 28(%eax), %ecx
 orl %ebp, %ebx
 movl %ecx, %ebp
 shll $24, %ebp
 orl %ebp, %ebx
 shrl $4, %ebx
 andl $67108863, %ebx
 movl %ebx, 608(%esp)
 movzbl 29(%eax), %ebx
 shll $8, %ebx
 movzbl 30(%eax), %ebp
 orl %ebx, %ecx
 shll $16, %ebp
 movzbl 31(%eax), %eax
 orl %ebp, %ecx
 shll $24, %eax
 xorl %ebp, %ebp
 orl %eax, %ecx
 movl $255, %eax
 shrl $6, %ecx
 movl %eax, %esi
 andl $33554431, %ecx
 movl %ecx, 612(%esp)
 movl %ebp, 616(%esp)
 movl %ebp, 620(%esp)
 movdqa 576(%esp), %xmm1
 movdqa 592(%esp), %xmm2
 movdqa 608(%esp), %xmm3
 movdqa %xmm1, 624(%esp)
 movdqa %xmm2, 640(%esp)
 movdqa %xmm3, 656(%esp)
 movdqa curve25519zeromodp2_sse2, %xmm4
 movdqa curve25519121665_sse2, %xmm3
 movdqa curve25519mask2625_sse2, %xmm2
 movdqa curve25519nineteen_sse2, %xmm1
 movdqa %xmm1, 16(%esp)
 movdqa %xmm2, 96(%esp)
 movdqa %xmm3, 112(%esp)
 movdqa %xmm4, 48(%esp)
 movdqa %xmm5, 32(%esp)
 movdqa %xmm6, 80(%esp)
 movl %edi, 76(%esp)
 movl %edx, %edi

Lmorebits:
 movl %esi, %ebx
 movl %esi, %ecx
 shrl $3, %ebx
 andl $7, %ecx
 movdqa 640(%esp), %xmm5
 pxor 496(%esp), %xmm5
 movdqa %xmm5, %xmm4
 movzbl (%edi,%ebx), %ebx
 shrl %cl, %ebx
 andl $1, %ebx
 xorl %ebx, %ebp
 negl %ebp
 movdqa 624(%esp), %xmm0
 movdqa 656(%esp), %xmm6
 pxor 480(%esp), %xmm0
 movd %ebp, %xmm2
 movdqa %xmm0, %xmm3
 pshufd $0, %xmm2, %xmm7
 movl %ebx, %ebp
 pand %xmm7, %xmm4
 pand %xmm7, %xmm3
 pxor 496(%esp), %xmm4
 pxor 512(%esp), %xmm6
 pxor %xmm4, %xmm5
 movdqa %xmm6, %xmm1
 movdqa %xmm5, 144(%esp)
 pand %xmm7, %xmm1
 movdqa 432(%esp), %xmm5
 pxor 480(%esp), %xmm3
 pxor 528(%esp), %xmm5
 pxor %xmm3, %xmm0
 pxor 512(%esp), %xmm1
 movdqa %xmm0, 128(%esp)
 movdqa %xmm5, %xmm0
 pxor %xmm1, %xmm6
 pand %xmm7, %xmm0
 movdqa %xmm6, 160(%esp)
 movdqa 448(%esp), %xmm6
 pxor 544(%esp), %xmm6
 pxor 528(%esp), %xmm0
 movdqa %xmm6, %xmm2
 pxor %xmm0, %xmm5
 pand %xmm7, %xmm2
 movdqa %xmm5, 176(%esp)
 movdqa 464(%esp), %xmm5
 pxor 560(%esp), %xmm5
 pxor 544(%esp), %xmm2
 pand %xmm5, %xmm7
 pxor %xmm2, %xmm6
 movdqa %xmm6, 192(%esp)
 movdqa %xmm2, %xmm6
 pxor 560(%esp), %xmm7
 paddd %xmm4, %xmm6
 movdqa %xmm6, 496(%esp)
 pxor %xmm7, %xmm5
 movdqa %xmm5, 224(%esp)
 movdqa %xmm0, %xmm5
 movdqa 80(%esp), %xmm6
 paddd %xmm3, %xmm5
 paddd %xmm6, %xmm3
 psubd %xmm0, %xmm3
 movd %xmm3, %eax
 movdqa %xmm3, %xmm0
 psrldq $4, %xmm0
 movdqa %xmm3, 528(%esp)
 movd %xmm0, %ecx
 movl %eax, %edx
 movdqa %xmm5, 480(%esp)
 movdqa 32(%esp), %xmm5
 shrl $26, %edx
 andl $67108863, %eax
 addl %edx, %ecx
 movl %ecx, %edx
 shrl $25, %ecx
 andl $33554431, %edx
 addl 536(%esp), %ecx
 movl %edx, 532(%esp)
 movl %ecx, %edx
 shrl $26, %ecx
 andl $67108863, %edx
 addl 540(%esp), %ecx
 paddd %xmm5, %xmm4
 movl %edx, 536(%esp)
 movl %ecx, %edx
 psubd %xmm2, %xmm4
 andl $33554431, %edx
 movl %edx, 540(%esp)
 movd %xmm4, %edx
 movdqa %xmm4, 544(%esp)
 shrl $25, %ecx
 addl %ecx, %edx
 movl %edx, %ecx
 shrl $26, %edx
 andl $67108863, %ecx
 addl 548(%esp), %edx
 movl %ecx, 544(%esp)
 movl %edx, %ecx
 shrl $25, %edx
 andl $33554431, %ecx
 addl 552(%esp), %edx
 movl %ecx, 548(%esp)
 movl %edx, %ecx
 shrl $26, %edx
 andl $67108863, %ecx
 addl 556(%esp), %edx
 movdqa %xmm7, 208(%esp)
 paddd %xmm1, %xmm7
 paddd 48(%esp), %xmm1
 movl %ecx, 552(%esp)
 movl %edx, %ecx
 psubd 208(%esp), %xmm1
 andl $33554431, %ecx
 movl %ecx, 556(%esp)
 movd %xmm1, %ecx
 movdqa %xmm1, 560(%esp)
 movdqa 176(%esp), %xmm1
 shrl $25, %edx
 addl %edx, %ecx
 movl %ecx, %edx
 shrl $26, %ecx
 andl $67108863, %edx
 addl 564(%esp), %ecx
 movl %edx, 560(%esp)
 movl %ecx, %edx
 shrl $25, %ecx
 andl $33554431, %edx
 imull $19, %ecx, %ecx
 movdqa %xmm7, 512(%esp)
 movdqa %xmm1, %xmm7
 movdqa 128(%esp), %xmm4
 paddd %xmm4, %xmm7
 paddd %xmm6, %xmm4
 psubd %xmm1, %xmm4
 addl %ecx, %eax
 movd %xmm4, %ecx
 movdqa %xmm4, %xmm1
 psrldq $4, %xmm1
 movdqa %xmm4, 432(%esp)
 movl %edx, 564(%esp)
 movd %xmm1, %edx
 movdqa 144(%esp), %xmm2
 movdqa 192(%esp), %xmm3
 movl %eax, 528(%esp)
 movl %ecx, %eax
 shrl $26, %eax
 paddd %xmm2, %xmm3
 addl %eax, %edx
 andl $67108863, %ecx
 movl %edx, %eax
 shrl $25, %edx
 andl $33554431, %eax
 addl 440(%esp), %edx
 movdqa %xmm3, 640(%esp)
 movl %eax, 436(%esp)
 movl %edx, %eax
 shrl $26, %edx
 andl $67108863, %eax
 movdqa 144(%esp), %xmm3
 addl 444(%esp), %edx
 paddd %xmm5, %xmm3
 movl %eax, 440(%esp)
 movl %edx, %eax
 psubd 192(%esp), %xmm3
 andl $33554431, %eax
 movl %eax, 444(%esp)
 movd %xmm3, %eax
 movdqa %xmm3, 448(%esp)
 shrl $25, %edx
 addl %edx, %eax
 movl %eax, %edx
 shrl $26, %eax
 andl $67108863, %edx
 addl 452(%esp), %eax
 movl %edx, 448(%esp)
 movl %eax, %edx
 shrl $25, %eax
 andl $33554431, %edx
 addl 456(%esp), %eax
 movdqa 160(%esp), %xmm0
 movl %edx, 452(%esp)
 movl %eax, %edx
 shrl $26, %eax
 andl $67108863, %edx
 movdqa 224(%esp), %xmm2
 addl 460(%esp), %eax
 paddd %xmm0, %xmm2
 paddd 48(%esp), %xmm0
 movl %edx, 456(%esp)
 movl %eax, %edx
 psubd 224(%esp), %xmm0
 andl $33554431, %edx
 movl %edx, 460(%esp)
 movd %xmm0, %edx
 movdqa %xmm0, 464(%esp)
 movdqa %xmm7, 624(%esp)
 shrl $25, %eax
 addl %eax, %edx
 movl %edx, %eax
 shrl $26, %edx
 andl $67108863, %eax
 addl 468(%esp), %edx
 movl %eax, 464(%esp)
 movl %edx, %eax
 shrl $25, %edx
 andl $33554431, %eax
 movl %eax, 468(%esp)
 imull $19, %edx, %eax
 lea 624(%esp), %edx
 movdqa %xmm2, 656(%esp)
 addl %eax, %ecx
 lea 672(%esp), %eax
 movl %ecx, 432(%esp)
 lea 528(%esp), %ecx
 call curve25519_mul_sse2
 lea 720(%esp), %eax
 lea 480(%esp), %edx
 lea 432(%esp), %ecx
 call curve25519_mul_sse2
 movdqa 720(%esp), %xmm6
 movdqa 672(%esp), %xmm0
 movdqa %xmm6, %xmm3
 paddd %xmm0, %xmm3
 paddd 80(%esp), %xmm0
 psubd %xmm6, %xmm0
 movdqa %xmm3, 672(%esp)
 movdqa %xmm0, %xmm3
 movd %xmm0, %eax
 psrldq $4, %xmm3
 movdqa %xmm0, 720(%esp)
 movd %xmm3, %ecx
 movl %eax, %edx
 movdqa 736(%esp), %xmm7
 movdqa 688(%esp), %xmm1
 movdqa %xmm7, %xmm4
 shrl $26, %edx
 paddd %xmm1, %xmm4
 addl %edx, %ecx
 andl $67108863, %eax
 movl %ecx, %edx
 shrl $25, %ecx
 andl $33554431, %edx
 addl 728(%esp), %ecx
 movl %edx, 724(%esp)
 movl %ecx, %edx
 shrl $26, %ecx
 andl $67108863, %edx
 addl 732(%esp), %ecx
 paddd 32(%esp), %xmm1
 movl %edx, 728(%esp)
 movl %ecx, %edx
 psubd %xmm7, %xmm1
 andl $33554431, %edx
 movl %edx, 732(%esp)
 movd %xmm1, %edx
 movdqa %xmm1, 736(%esp)
 movdqa 704(%esp), %xmm2
 shrl $25, %ecx
 addl %ecx, %edx
 movl %edx, %ecx
 shrl $26, %edx
 andl $67108863, %ecx
 addl 740(%esp), %edx
 movl %ecx, 736(%esp)
 movl %edx, %ecx
 shrl $25, %edx
 andl $33554431, %ecx
 addl 744(%esp), %edx
 movl %ecx, 740(%esp)
 movl %edx, %ecx
 shrl $26, %edx
 andl $67108863, %ecx
 movdqa 752(%esp), %xmm5
 addl 748(%esp), %edx
 paddd %xmm2, %xmm5
 paddd 48(%esp), %xmm2
 movl %ecx, 744(%esp)
 movl %edx, %ecx
 psubd 752(%esp), %xmm2
 andl $33554431, %ecx
 movl %ecx, 748(%esp)
 movd %xmm2, %ecx
 movdqa %xmm2, 752(%esp)
 movdqa %xmm4, 688(%esp)
 shrl $25, %edx
 addl %edx, %ecx
 movl %ecx, %edx
 shrl $26, %ecx
 andl $67108863, %edx
 addl 756(%esp), %ecx
 movl %edx, 752(%esp)
 movl %ecx, %edx
 shrl $25, %ecx
 andl $33554431, %edx
 imull $19, %ecx, %ecx
 movdqa %xmm5, 704(%esp)
 addl %ecx, %eax
 movl $1, %ecx
 movl %edx, 756(%esp)
 lea 720(%esp), %edx
 movl %eax, 720(%esp)
 lea 768(%esp), %eax
 call curve25519_square_times_sse2
 movl $1, %ecx
 lea 624(%esp), %eax
 lea 672(%esp), %edx
 call curve25519_square_times_sse2
 lea 432(%esp), %eax
 lea 768(%esp), %edx
 lea 576(%esp), %ecx
 call curve25519_mul_sse2
 movl $1, %ecx
 lea 816(%esp), %eax
 lea 480(%esp), %edx
 call curve25519_square_times_sse2
 movl $1, %ecx
 lea 864(%esp), %eax
 lea 528(%esp), %edx
 call curve25519_square_times_sse2
 lea 480(%esp), %eax
 lea 816(%esp), %edx
 lea 864(%esp), %ecx
 call curve25519_mul_sse2
 movdqa 80(%esp), %xmm2
 paddd 816(%esp), %xmm2
 pxor %xmm6, %xmm6
 psubd 864(%esp), %xmm2
 movd %xmm2, %eax
 movdqa %xmm2, %xmm5
 psrldq $4, %xmm5
 movdqa %xmm2, 864(%esp)
 movd %xmm5, %ecx
 movl %eax, %edx
 movdqa 32(%esp), %xmm1
 paddd 832(%esp), %xmm1
 shrl $26, %edx
 andl $67108863, %eax
 addl %edx, %ecx
 movl %ecx, %edx
 shrl $25, %ecx
 andl $33554431, %edx
 addl 872(%esp), %ecx
 movl %edx, 868(%esp)
 movl %ecx, %edx
 shrl $26, %ecx
 andl $67108863, %edx
 addl 876(%esp), %ecx
 movl %edx, 872(%esp)
 movl %ecx, %edx
 psubd 880(%esp), %xmm1
 andl $33554431, %edx
 movl %edx, 876(%esp)
 movd %xmm1, %edx
 movdqa %xmm1, 880(%esp)
 movdqa 48(%esp), %xmm3
 shrl $25, %ecx
 addl %ecx, %edx
 movl %edx, %ecx
 shrl $26, %edx
 andl $67108863, %ecx
 addl 884(%esp), %edx
 movl %ecx, 880(%esp)
 movl %edx, %ecx
 shrl $25, %edx
 andl $33554431, %ecx
 addl 888(%esp), %edx
 movl %ecx, 884(%esp)
 movl %edx, %ecx
 shrl $26, %edx
 andl $67108863, %ecx
 addl 892(%esp), %edx
 paddd 848(%esp), %xmm3
 movl %ecx, 888(%esp)
 movl %edx, %ecx
 psubd 896(%esp), %xmm3
 andl $33554431, %ecx
 movl %ecx, 892(%esp)
 movd %xmm3, %ecx
 movdqa %xmm3, 896(%esp)
 movdqa 112(%esp), %xmm7
 shrl $25, %edx
 addl %edx, %ecx
 movl %ecx, %edx
 shrl $26, %ecx
 andl $67108863, %edx
 addl 900(%esp), %ecx
 movl %edx, 896(%esp)
 movl %ecx, %edx
 shrl $25, %ecx
 andl $33554431, %edx
 imull $19, %ecx, %ecx
 movdqa 880(%esp), %xmm3
 addl %ecx, %eax
 lea 912(%esp), %ecx
 movl %eax, 864(%esp)
 lea 528(%esp), %eax
 movdqa 864(%esp), %xmm4
 movdqa %xmm4, %xmm0
 punpckldq %xmm6, %xmm0
 pmuludq %xmm7, %xmm0
 movdqa %xmm0, %xmm5
 psrlq $26, %xmm5
 pslldq $8, %xmm5
 punpckhdq %xmm6, %xmm4
 paddq %xmm5, %xmm0
 pmuludq %xmm7, %xmm4
 movdqa %xmm0, %xmm1
 psrlq $25, %xmm1
 psrldq $8, %xmm1
 paddq %xmm1, %xmm4
 movdqa %xmm4, %xmm5
 movdqa %xmm3, %xmm1
 psrlq $26, %xmm5
 pslldq $8, %xmm5
 punpckldq %xmm6, %xmm1
 paddq %xmm5, %xmm4
 pmuludq %xmm7, %xmm1
 movdqa %xmm4, %xmm5
 psrlq $25, %xmm5
 psrldq $8, %xmm5
 paddq %xmm5, %xmm1
 movdqa %xmm1, %xmm5
 psrlq $26, %xmm5
 pslldq $8, %xmm5
 punpckhdq %xmm6, %xmm3
 movl %edx, 900(%esp)
 lea 864(%esp), %edx
 paddq %xmm5, %xmm1
 pmuludq %xmm7, %xmm3
 movdqa 896(%esp), %xmm2
 punpckldq %xmm6, %xmm2
 movdqa %xmm1, %xmm6
 psrlq $25, %xmm6
 psrldq $8, %xmm6
 paddq %xmm6, %xmm3
 pmuludq %xmm7, %xmm2
 movdqa %xmm3, %xmm5
 psrlq $26, %xmm5
 pslldq $8, %xmm5
 paddq %xmm5, %xmm3
 movdqa %xmm3, %xmm7
 psrlq $25, %xmm7
 psrldq $8, %xmm7
 paddq %xmm7, %xmm2
 movdqa %xmm2, %xmm5
 psrlq $26, %xmm5
 pslldq $8, %xmm5
 paddq %xmm5, %xmm2
 movdqa %xmm2, %xmm6
 psrlq $25, %xmm6
 psrldq $8, %xmm6
 pmuludq 16(%esp), %xmm6
 movdqa 96(%esp), %xmm5
 pand %xmm5, %xmm0
 pand %xmm5, %xmm4
 paddq %xmm6, %xmm0
 pand %xmm5, %xmm3
 pand %xmm5, %xmm1
 pshufd $143, %xmm4, %xmm4
 pand %xmm5, %xmm2
 pshufd $248, %xmm0, %xmm0
 pshufd $143, %xmm3, %xmm3
 por %xmm0, %xmm4
 pshufd $248, %xmm1, %xmm1
 pshufd $248, %xmm2, %xmm2
 por %xmm1, %xmm3
 paddd 816(%esp), %xmm4
 paddd 832(%esp), %xmm3
 paddd 848(%esp), %xmm2
 movdqa %xmm4, 912(%esp)
 movdqa %xmm3, 928(%esp)
 movdqa %xmm2, 944(%esp)
 call curve25519_mul_sse2
 decl %esi
 cmpl $-1, %esi
 jne Lmorebits

 negl %ebx
 lea 144(%esp), %eax
 movdqa 480(%esp), %xmm2
 lea 528(%esp), %edx
 movdqa 624(%esp), %xmm6
 movl $1, %ecx
 pxor %xmm2, %xmm6
 movd %ebx, %xmm1
 movdqa %xmm6, %xmm4
 movdqa 496(%esp), %xmm3
 movdqa 640(%esp), %xmm7
 pshufd $0, %xmm1, %xmm0
 pxor %xmm3, %xmm7
 pand %xmm0, %xmm4
 movdqa %xmm7, %xmm5
 movdqa 512(%esp), %xmm1
 pxor %xmm2, %xmm4
 movdqa 656(%esp), %xmm2
 pand %xmm0, %xmm5
 pxor %xmm1, %xmm2
 pxor %xmm3, %xmm5
 movdqa %xmm2, %xmm3
 pxor %xmm4, %xmm6
 pand %xmm0, %xmm3
 pxor %xmm5, %xmm7
 movdqa %xmm4, 480(%esp)
 pxor %xmm1, %xmm3
 movdqa 528(%esp), %xmm4
 pxor %xmm3, %xmm2
 movdqa 432(%esp), %xmm1
 pxor %xmm4, %xmm1
 movdqa %xmm5, 496(%esp)
 movdqa %xmm2, 656(%esp)
 movdqa %xmm6, 624(%esp)
 movdqa %xmm1, %xmm6
 movdqa 544(%esp), %xmm5
 pand %xmm0, %xmm6
 movdqa 448(%esp), %xmm2
 pxor %xmm4, %xmm6
 movdqa %xmm7, 640(%esp)
 pxor %xmm5, %xmm2
 movdqa %xmm3, 512(%esp)
 movdqa %xmm2, %xmm4
 movdqa 560(%esp), %xmm7
 pand %xmm0, %xmm4
 movdqa 464(%esp), %xmm3
 pxor %xmm5, %xmm4
 pxor %xmm7, %xmm3
 pxor %xmm6, %xmm1
 pand %xmm3, %xmm0
 pxor %xmm4, %xmm2
 pxor %xmm7, %xmm0
 pxor %xmm0, %xmm3
 movl 76(%esp), %edi
 movdqa %xmm6, 528(%esp)
 movdqa %xmm4, 544(%esp)
 movdqa %xmm1, 432(%esp)
 movdqa %xmm2, 448(%esp)
 movdqa %xmm3, 464(%esp)
 movdqa %xmm0, 560(%esp)
 call curve25519_square_times_sse2
 movl $2, %ecx
 lea 192(%esp), %eax
 lea 144(%esp), %edx
 call curve25519_square_times_sse2
 lea 240(%esp), %eax
 lea 192(%esp), %edx
 lea 528(%esp), %ecx
 call curve25519_mul_sse2
 lea 144(%esp), %eax
 movl %eax, %ecx
 lea 240(%esp), %edx
 call curve25519_mul_sse2
 movl $1, %ecx
 lea 192(%esp), %eax
 lea 144(%esp), %edx
 call curve25519_square_times_sse2
 lea 240(%esp), %eax
 movl %eax, %ecx
 lea 192(%esp), %edx
 call curve25519_mul_sse2
 movl $5, %ecx
 lea 288(%esp), %eax
 lea 240(%esp), %edx
 call curve25519_square_times_sse2
 lea 240(%esp), %eax
 movl %eax, %ecx
 lea 288(%esp), %edx
 call curve25519_mul_sse2
 movl $10, %ecx
 lea 288(%esp), %eax
 lea 240(%esp), %edx
 call curve25519_square_times_sse2
 lea 336(%esp), %eax
 lea 288(%esp), %edx
 lea 240(%esp), %ecx
 call curve25519_mul_sse2
 movl $20, %ecx
 lea 288(%esp), %eax
 lea 336(%esp), %edx
 call curve25519_square_times_sse2
 lea 288(%esp), %eax
 movl %eax, %edx
 lea 336(%esp), %ecx
 call curve25519_mul_sse2
 movl $10, %ecx
 lea 288(%esp), %eax
 movl %eax, %edx
 call curve25519_square_times_sse2
 lea 240(%esp), %eax
 movl %eax, %ecx
 lea 288(%esp), %edx
 call curve25519_mul_sse2
 movl $50, %ecx
 lea 288(%esp), %eax
 lea 240(%esp), %edx
 call curve25519_square_times_sse2
 lea 336(%esp), %eax
 lea 288(%esp), %edx
 lea 240(%esp), %ecx
 call curve25519_mul_sse2
 movl $100, %ecx
 lea 288(%esp), %eax
 lea 336(%esp), %edx
 call curve25519_square_times_sse2
 lea 288(%esp), %eax
 movl %eax, %edx
 lea 336(%esp), %ecx
 call curve25519_mul_sse2
 movl $50, %ecx
 lea 288(%esp), %eax
 movl %eax, %edx
 call curve25519_square_times_sse2
 lea 240(%esp), %eax
 movl %eax, %ecx
 lea 288(%esp), %edx
 call curve25519_mul_sse2
 movl $5, %ecx
 lea 240(%esp), %eax
 movl %eax, %edx
 call curve25519_square_times_sse2
 lea 384(%esp), %eax
 lea 240(%esp), %edx
 lea 144(%esp), %ecx
 call curve25519_mul_sse2
 lea 528(%esp), %eax
 lea 480(%esp), %edx
 lea 384(%esp), %ecx
 call curve25519_mul_sse2
 movdqa 528(%esp), %xmm6
 movd %xmm6, %ebx
 movdqa %xmm6, %xmm2
 psrldq $4, %xmm2
 movdqa %xmm6, %xmm3
 psrldq $8, %xmm3
 movdqa %xmm6, %xmm4
 movd %xmm2, %eax
 movl %ebx, %ecx
 psrldq $12, %xmm4
 movdqa 544(%esp), %xmm5
 shrl $26, %ecx
 movdqa %xmm5, %xmm0
 addl %ecx, %eax
 movdqa %xmm5, %xmm1
 movl %edi, 76(%esp)
 movl %eax, %edx
 movd %xmm3, %edi
 movdqa %xmm5, %xmm7
 movd %xmm4, %ecx
 psrldq $4, %xmm0
 psrldq $8, %xmm1
 shrl $25, %edx
 andl $67108863, %ebx
 addl %edx, %edi
 andl $33554431, %eax
 movl %edi, %ebp
 andl $67108863, %edi
 shrl $26, %ebp
 addl %ebp, %ecx
 movd %xmm5, %edx
 movl %ecx, %esi
 psrldq $12, %xmm7
 movdqa %xmm7, 80(%esp)
 shrl $25, %esi
 andl $33554431, %ecx
 addl %esi, %edx
 movd %xmm0, %esi
 movl %edx, %ebp
 movdqa 560(%esp), %xmm7
 movdqa %xmm7, 128(%esp)
 shrl $26, %ebp
 andl $67108863, %edx
 addl %ebp, %esi
 movd %xmm1, %ebp
 psrldq $4, %xmm7
 movdqa %xmm6, 96(%esp)
 movl %esi, 16(%esp)
 shrl $25, %esi
 addl %esi, %ebp
 movl %ebp, 20(%esp)
 shrl $26, %ebp
 movl 80(%esp), %esi
 addl %ebp, %esi
 movl %esi, 24(%esp)
 shrl $25, %esi
 movl 560(%esp), %ebp
 addl %esi, %ebp
 movl %ebp, 28(%esp)
 movl %ebp, %esi
 movd %xmm7, %ebp
 movdqa %xmm5, 112(%esp)
 shrl $26, %esi
 addl %esi, %ebp
 movl %ebp, %esi
 andl $33554431, %ebp
 shrl $25, %esi
 imull $19, %esi, %esi
 addl %esi, %ebx
 movl %ebx, %esi
 andl $67108863, %ebx
 shrl $26, %esi
 addl %esi, %eax
 movl %eax, %esi
 andl $33554431, %eax
 shrl $25, %esi
 addl %edi, %esi
 movl %esi, %edi
 andl $67108863, %esi
 shrl $26, %edi
 addl %ecx, %edi
 movl %edi, %ecx
 andl $33554431, %edi
 shrl $25, %ecx
 addl %edx, %ecx
 movl 16(%esp), %edx
 movl %ecx, 32(%esp)
 andl $33554431, %edx
 shrl $26, %ecx
 addl %edx, %ecx
 movl 20(%esp), %edx
 movl %ecx, 36(%esp)
 andl $67108863, %edx
 shrl $25, %ecx
 addl %edx, %ecx
 movl 24(%esp), %edx
 movl %ecx, 40(%esp)
 andl $33554431, %edx
 shrl $26, %ecx
 addl %edx, %ecx
 movl %ecx, %edx
 movl %ecx, 44(%esp)
 movl 28(%esp), %ecx
 shrl $25, %edx
 andl $67108863, %ecx
 addl %ecx, %edx
 movl %edx, %ecx
 andl $67108863, %edx
 shrl $26, %ecx
 addl %ebp, %ecx
 movl %ecx, %ebp
 andl $33554431, %ecx
 shrl $25, %ebp
 imull $19, %ebp, %ebp
 lea 19(%ebx,%ebp), %ebx
 movl %ebx, %ebp
 andl $67108863, %ebx
 shrl $26, %ebp
 addl %ebp, %eax
 movl %eax, %ebp
 andl $33554431, %eax
 shrl $25, %ebp
 addl %esi, %ebp
 movl %ebp, %esi
 andl $67108863, %ebp
 shrl $26, %esi
 addl %edi, %esi
 movl %eax, 100(%esp)
 movl %esi, %eax
 movl 32(%esp), %edi
 andl $33554431, %esi
 shrl $25, %eax
 andl $67108863, %edi
 addl %edi, %eax
 movl %eax, %edi
 andl $67108863, %eax
 movl %esi, 108(%esp)
 movl 36(%esp), %esi
 shrl $26, %edi
 andl $33554431, %esi
 addl %esi, %edi
 movl %ebp, 104(%esp)
 movl %edi, %ebp
 movl %eax, 112(%esp)
 andl $33554431, %edi
 movl 40(%esp), %eax
 shrl $25, %ebp
 andl $67108863, %eax
 addl %eax, %ebp
 movl %edi, 116(%esp)
 movl %ebp, %edi
 movl 44(%esp), %esi
 andl $67108863, %ebp
 shrl $26, %edi
 andl $33554431, %esi
 addl %esi, %edi
 movl %ebp, 120(%esp)
 movl %edi, %ebp
 shrl $25, %ebp
 andl $33554431, %edi
 addl %edx, %ebp
 movl %ebp, %esi
 andl $67108863, %ebp
 shrl $26, %esi
 movl %edi, 124(%esp)
 movdqa 112(%esp), %xmm4
 paddd 16+curve25519offset_sse2, %xmm4
 movdqa %xmm4, %xmm5
 lea (%ecx,%esi), %edx
 shrl $25, %edx
 movdqa %xmm4, %xmm6
 imull $19, %edx, %eax
 movdqa %xmm4, %xmm7
 psrldq $4, %xmm5
 psrldq $8, %xmm6
 psrldq $12, %xmm7
 movdqa %xmm4, 112(%esp)
 addl %eax, %ebx
 movl %ebx, 96(%esp)
 lea -1(%esi,%ecx), %ebx
 movdqa 96(%esp), %xmm0
 paddd curve25519offset_sse2, %xmm0
 movd %xmm0, %ecx
 movdqa %xmm0, %xmm1
 psrldq $4, %xmm1
 movdqa %xmm0, %xmm2
 psrldq $8, %xmm2
 movdqa %xmm0, %xmm3
 movd %xmm1, %edx
 movl %ecx, %eax
 psrldq $12, %xmm3
 movdqa %xmm0, 96(%esp)
 shrl $26, %eax
 andl $67108863, %ecx
 addl %eax, %edx
 movl %ecx, 52(%esp)
 movl %edx, %esi
 movd %xmm2, %ecx
 andl $33554431, %edx
 movd %xmm3, %eax
 shrl $25, %esi
 addl %esi, %ecx
 movl %ecx, %edi
 andl $67108863, %ecx
 shrl $26, %edi
 addl %edi, %eax
 movl %ebx, 48(%esp)
 movl %eax, %esi
 movd %xmm4, %ebx
 andl $33554431, %eax
 shrl $25, %esi
 addl %esi, %ebx
 movl %ebx, 56(%esp)
 movl %ebx, %edi
 movd %xmm5, %ebx
 shrl $26, %edi
 addl %edi, %ebx
 movl %ebx, 60(%esp)
 movl %ebx, %esi
 movd %xmm6, %ebx
 shrl $25, %esi
 addl %esi, %ebx
 movl %ebx, 64(%esp)
 movd %xmm7, %ebx
 movl 64(%esp), %edi
 shrl $26, %edi
 addl %edi, %ebx
 movl %ebx, 68(%esp)
 shrl $25, %ebx
 movl 76(%esp), %esi
 shll $2, %edx
 shll $3, %ecx
 shll $5, %eax
 lea 67108863(%ebx,%ebp), %ebp
 movl 64(%esp), %ebx
 andl $67108863, %ebx
 addl %ebx, %ebx
 movl %ebx, 64(%esp)
 movl 68(%esp), %ebx
 andl $33554431, %ebx
 shll $3, %ebx
 movl %ebx, 68(%esp)
 movl %ebp, %ebx
 andl $67108863, %ebx
 shrl $26, %ebp
 shll $4, %ebx
 movl %ebx, 72(%esp)
 movl 48(%esp), %ebx
 addl %ebp, %ebx
 andl $33554431, %ebx
 shll $6, %ebx
 movl %ebx, 48(%esp)
 movl 52(%esp), %ebx
 movb %bl, (%esi)
 shrl $8, %ebx
 movb %bl, 1(%esi)
 movl 52(%esp), %ebx
 shrl $16, %ebx
 movb %bl, 2(%esi)
 movl 52(%esp), %ebx
 shrl $24, %ebx
 orl %edx, %ebx
 movb %bl, 3(%esi)
 movl %edx, %ebx
 shrl $8, %ebx
 movb %bl, 4(%esi)
 movl %edx, %ebx
 shrl $24, %edx
 shrl $16, %ebx
 orl %ecx, %edx
 movb %bl, 5(%esi)
 movl %ecx, %ebx
 movb %dl, 6(%esi)
 movl %ecx, %edx
 shrl $24, %ecx
 shrl $8, %edx
 orl %eax, %ecx
 shll $6, 56(%esp)
 movb %dl, 7(%esi)
 movl %eax, %edx
 movb %cl, 9(%esi)
 movl %eax, %ecx
 shrl $24, %eax
 orl 56(%esp), %eax
 andl $33554431, 60(%esp)
 movb %al, 12(%esi)
 movl 56(%esp), %eax
 shrl $8, %eax
 movb %al, 13(%esi)
 movl 60(%esp), %eax
 shrl $16, %ebx
 shrl $8, %ecx
 movb %bl, 8(%esi)
 movl %eax, %ebx
 movb %cl, 10(%esi)
 movl 56(%esp), %ecx
 shrl $16, %ecx
 movb %cl, 14(%esi)
 movl %eax, %ecx
 movb %al, 16(%esi)
 shrl $24, %eax
 shrl $8, %ebx
 movb %bl, 17(%esi)
 movl 64(%esp), %ebx
 orl %ebx, %eax
 shrl $16, %edx
 movb %al, 19(%esi)
 movl %ebx, %eax
 movb %dl, 11(%esi)
 movl 56(%esp), %edx
 shrl $16, %ecx
 shrl $24, %edx
 movb %cl, 18(%esi)
 movl %ebx, %ecx
 shrl $24, %ebx
 movb %dl, 15(%esi)
 shrl $8, %eax
 movl 68(%esp), %edx
 orl %edx, %ebx
 movb %al, 20(%esi)
 movl %edx, %eax
 shrl $16, %ecx
 movb %bl, 22(%esi)
 movl %edx, %ebx
 shrl $24, %edx
 movb %cl, 21(%esi)
 shrl $16, %eax
 movl 72(%esp), %ecx
 orl %ecx, %edx
 movb %al, 24(%esi)
 movl %ecx, %eax
 movb %dl, 25(%esi)
 movl %ecx, %edx
 shrl $24, %ecx
 shrl $16, %eax
 movb %al, 27(%esi)
 movl 48(%esp), %eax
 orl %eax, %ecx
 shrl $8, %ebx
 movb %bl, 23(%esi)
 movl %eax, %ebx
 movb %cl, 28(%esi)
 movl %eax, %ecx
 shrl $8, %edx
 shrl $8, %ecx
 shrl $16, %ebx
 shrl $24, %eax
 movb %dl, 26(%esi)
 movb %cl, 29(%esi)
 movb %bl, 30(%esi)
 movb %al, 31(%esi)
 addl $972, %esp
 popl %ebp
 popl %ebx
 popl %edi
 popl %esi
 ret $4

.globl _curve25519_donna
.globl curve25519_donna
_curve25519_donna:
curve25519_donna:
 pushl %ebp
 mov %esp, %ebp
 andl $4294967280, %esp
 subl $64, %esp
 movl 12(%ebp), %ecx
 movl 16(%ebp), %eax
 movdqu 16(%ecx), %xmm1
 movdqu (%ecx), %xmm0
 movdqa %xmm1, 16(%esp)
 psrlw $8, %xmm1
 pextrw $7, %xmm1, %ecx
 pextrw $0, %xmm0, %edx
 andl $127, %ecx
 andl $-8, %edx
 movdqa %xmm0, (%esp)
 orl $64, %ecx
 movb %dl, (%esp)
 movb %cl, 31(%esp)
 addl $-16, %esp
 movl 8(%ebp), %ecx
 lea 16(%esp), %edx
 movl %eax, (%esp)
 call curve25519_scalarmult_sse2
 xorl %eax, %eax
 mov %ebp, %esp
 popl %ebp
 ret

.data
.section .rodata
.p2align 5

.globl curve25519zeromodp0_sse2
.globl curve25519zeromodp1_sse2
.globl curve25519zeromodp2_sse2
.globl curve25519topmask_sse2
.globl curve25519mask2625_sse2
.globl curve25519nineteen_sse2
.globl curve25519121665_sse2
.globl curve25519bottommask_sse2
.globl curve25519nineteen2x_sse2
.globl curve25519one_sse2
.globl curve25519offset_sse2

	.align 16
curve25519zeromodp0_sse2:
	.long	0x7ffffda,0x3fffffe,0x7fffffe,0x3fffffe
	.align 16
curve25519zeromodp1_sse2:
	.long	0x7fffffe,0x3fffffe,0x7fffffe,0x3fffffe
	.align 16
curve25519zeromodp2_sse2:
	.long	0x7fffffe,0x3fffffe,0,0
	.align 16
curve25519topmask_sse2:
	.long	0,0,0xffffffff,0xffffffff
	.align 16
curve25519mask2625_sse2:
	.long	0x3ffffff,0,0x1ffffff,0
	.align 16
curve25519nineteen_sse2:
	.long	19,0,19,0
	.align 16
curve25519121665_sse2:
	.long	121665,0,121665,0
	.align 16
curve25519bottommask_sse2:
	.long	0xffffffff,0xffffffff,0,0
	.align 16
curve25519nineteen2x_sse2:
	.long	38,0,19,0
	.align 16
curve25519one_sse2:
	.long	1,0,0,0,0,0,0,0,0,0,0,0
	.align 16
curve25519offset_sse2:
	.long	0x3ffffed,0x1ffffff,0x3ffffff,0x1ffffff,0x3ffffff,0x1ffffff,0x3ffffff,0x1ffffff,0x3ffffff,0x1ffffff,0,0

