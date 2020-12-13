
.intel_syntax noprefix

.global _asm3

_asm3:
	push   ebp
	mov    ebp,esp
	xor    eax,eax
	mov    ah,BYTE PTR [ebp+0xa]
	shl    ax,0x10
	sub    al,BYTE PTR [ebp+0xf]
	add    ah,BYTE PTR [ebp+0xe]
	
	nop
	pop    ebp
	ret    

