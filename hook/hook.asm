_TEXT SEGMENT

EXTERN Status: PROC
EXTERN trampoline: qword

hook_handler PROC

    ; Сохраняем регистры
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
	
	sub rsp, 32         ; shadow space для Status()

    ; Status() вызывается без аргументов, берёт данные из глобальных переменных
    call Status
	
	add rsp, 32		     ; Восстанавливаем стек

    ; Восстанавливаем регистры
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    jmp trampoline           ; Переход к trampoline

hook_handler ENDP

_TEXT ENDS
END