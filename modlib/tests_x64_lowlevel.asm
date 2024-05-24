tests SEGMENT read write execute

PUBLIC DummyFuncStartLabel
PUBLIC DummyFuncMidLabel
EXTERNDEF evil: DWORD

; this has to be very closely synchronized with TestLLHook
DummyFunc PROC
nop

; NO idea why, but placing DummyFuncStartLabel at the same address as DummyFunc
; causes `&DummyFuncStartLabel` and even `addressof(DummyFuncStartLabel)` to
; reference a jump table entry.
; furthermore, we have to fully clean the solution and rebuild when moving
; labels, so be careful with that lol
DummyFuncStartLabel::
mov rax, 4455
mov rbx, 6677
mov rcx, 8899

; safety nops lol
nop
nop
nop
nop
nop

DummyFuncMidLabel::
mov rax, 1122
mov rbx, 2233
mov rcx, 3344

; safety nops lol
nop
nop
nop
nop
nop

ret

DummyFunc ENDP 


END
