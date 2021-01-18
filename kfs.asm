
; Copyright achiu-au (aka MaoKo)
; You can compile with fasm (https://flatassembler.net/)

format ELF executable 3H at 0500000H
entry _kernel_elf_entry

; DEBUG

macro _itoa number* {
    local _number, _modulo, _length
    _number = (number)
    if (_number < $00)
        db "-"
        _number = (-_number)
    end if
    _length = $00
    if (~(definite __itoa_virtual))
        virtual at $00
            __itoa_virtual::
        end virtual
    end if
    assert (_number eqtype $00)
    while _number
        _modulo = _number mod $10
        _number = _number / $10
        _length = _length + $01
        virtual __itoa_virtual
            if (_modulo >= 00AH)
                db ((_modulo-00AH)+"A")
            else
                db (_modulo+"0")
            end if
        end virtual
    end while
    repeat _length
        virtual __itoa_virtual
            load _number byte from __itoa_virtual:($-(%))
        end virtual
        db _number
    end repeat
}

; DEBUG

macro __transform_struc [_item*]
{
forward
    macro _item _param&
    \{
        \local _private
        _private _item _param
    \}
}

_PRESENT = 080H
rept 4H i:0H
{
    _DPL#i = ((i) shl 5H)
    _RPL#i = (i)
}
_DESCRIPTOR = 010H
_EXECUTABLE = 8H
_CONFORMING = 4H
_EXPAND_DOWN = 4H
_READABLE = 2H
_WRITABLE = 2H
_ACCESS = 1H

_BUSY = 2H
_TI = 4H

_286_TSS = 1H
_286_LDT = 2H
_286_CALL_GATE = 4H
_286_TASK_GATE = 5H
_286_INTERRUPT_GATE = 6H
_286_TRAP_GATE = 7H

_386_TSS = 9H
_386_CALL_GATE = 00CH
_386_INTERRUPT_GATE = 00EH
_386_TRAP_GATE = 00FH

_L = (2H shl 4H)
_D = (4H shl 4H)
_B = (4H shl 4H)
_G = (8H shl 4H)

struc TSS_16 _link*, _sp0*, _ss0*, _sp1*, _ss1*, _sp2*, _ss2*, _ip*, _flag*, _ax*, _cx*, _dx*, _bx*, _sp*, _bp*, _si*, _di*, _es*, _cs*, _ss*, _ds*, _ldt*
{
    .link: dw _link
    .sp0: dw _ss0
    .ss0: dw _sp0
    .sp1: dw _sp1
    .ss1: dw _ss1
    .sp2: dw _sp2
    .ss2: dw _ss2
    .ip: dw _ip
    .flag: dw _flag
    .ax: dw _ax
    .cx: dw _cx
    .dx: dw _dx
    .bx: dw _bx
    .sp: dw _sp
    .bp: dw _bp
    .si: dw _si
    .di: dw _di
    .es: dw _es
    .cs: dw _cs
    .ds: dw _ds
    .ss: dw _ss
    .ldt: dw _ldt
}

struc TSS_32 _link*, _esp0*, _ss0*, _esp1*, _ss1*, _esp2*, _ss2*, _cr3*, _eip*, _eflag*, _eax*, _ecx*, _edx*, _ebx*, _esp*, _ebp*, _esi*, _edi*, _es*, _cs*, _ss*, _ds*, _fs*, _gs*, _ldt*, _trap*, _iomap*
{
    assert (((_trap) >= 0H) & ((_trap) <= 1H))
    .link: dw _link
    dw 0H
    .esp0: dd _esp0
    .ss0: dw _ss0
    dw 0H
    .esp1: dd _esp1
    .ss1: dw _ss1
    dw 0H
    .esp2: dd _esp2
    .ss2: dw _ss2
    dw 0H
    .cr3: dd _cr3
    .eip: dd _eip
    .eflag: dd _eflag
    .eax: dd _eax
    .ecx: dd _ecx
    .edx: dd _edx
    .ebx: dd _ebx
    .esp: dd _esp
    .ebp: dd _ebp
    .esi: dd _esi
    .edi: dd _edi
    .es: dw _es
    dw 0H
    .cs: dw _cs
    dw 0H
    .ss: dw _ss
    dw 0H
    .ds: dw _ds
    dw 0H
    .fs: dw _fs
    dw 0H
    .gs: dw _gs
    dw 0H
    .ldt: dw _ldt
    dw 0H
    .trap: dw (_trap)
    .iomap: dw _iomap
}

__transform_struc TSS_16, TSS_32

macro descriptor_table _name*, _local:0H
{
    local _selector, _retreive
    _selector = 0H

    macro _retreive _target*
    \{
        local _mask
        _mask = 0H
        _target:
        if (_local)
            _mask = _TI
        end if
        _target\#.selector = (((_selector) * 8H) or _mask)
        _selector = ((_selector) + 1H)
    \}

    struc DT_null
    \{
        _retreive .
        dq 0H
    \}

    struc DT_dte _flag*, _access*, _offset*, _limit*
    \{
        _retreive .
        assert (((_limit) >= 0H) & ((_limit) <= 00FFFFFH))
        assert (((_offset) >= 0H) & ((_offset) <= 0FFFFFFFFH))
        .limit_1: dw ((_limit) and 0FFFFH)
        .offset_1: dw ((_offset) and 0FFFFH)
        .offset_2: db (((_offset) shr 010H) and 0FFH)
        .access: db ((_access) or _DESCRIPTOR)
        .limit_2:
        .flag: db ((_flag) or ((_limit) shr 010H))
        .offset_3: db ((_offset) shr 018H)
    \}

    struc DT_gte _access*, _wdcnt*, _select*, _offset*
    \{
        _retreive .
        assert (((_offset) >= 0H) & ((_offset) <= 0FFFFFFFFH))
        assert (((_select) >= 0H) & ((_select) <= 0FFFFH))
        assert (((_wdcnt) >= 0H) & ((_wdcnt) <= 01FH))
        .offset_1: dw ((_offset) and 0FFFFH)
        .select: dw (_select)
        .wdcnt: db (_wdcnt)
        .access: db ((_access) and (not _DESCRIPTOR))
        .offset_2: dw ((_offset) shr 010H)
    \}

    struc DT_ste _access*, _offset*, _limit*
    \{
        _retreive .
        assert (((_limit) >= 0H) & ((_limit) <= 00FFFFFH))
        assert (((_offset) >= 0H) & ((_offset) <= 0FFFFFFFFH))
        .limit_1: dw ((_limit) and 0FFFFH)
        .offset_1: dw ((_offset) and 0FFFFH)
        .offset_2: db (((_offset) shr 010H) and 0FFH)
        .access: db ((_access) and (not _DESCRIPTOR))
        .limit_2: db ((_limit) shr 010H)
        .offset_3: db ((_offset) shr 018H)
    \}

    __transform_struc DT_null, DT_dte, DT_gte, DT_ste
    psegment _name
}

_context = ($)
define _restore
macro psegment _name*, _mode:use32
{
    local _base
    _base = ($)
    match,_restore \{ _context = (_base) \}
    match _, _restore \{ _context = (_context + (_base)) \}
    define _restore _base,_name
    label _name#.start at 0H
    label _name at _context
    org 0H
    _mode
}

macro _segsize _target*, _size*
{
    _target = ((_size) - 1H)
    assert ((_target) >= 0H)
}

macro reserve _name*, _origin*, _size*
{
    label _name at (_origin)
    label _name#.start at 0H
    _segsize _name#.size, (_size)
}

macro end _continue*
{
    local _missed
    define _missed
    match =psegment, _continue \{ define _missed 1 \}
    match =descriptor_table, _continue \{ define _missed 2 \}
    match _, _missed
    \{
        match =2, _
        \\{
            restruc DT_null, DT_dte, DT_gte, DT_ste
            purge DT_null, DT_dte, DT_gte, DT_ste
        \\}
        match _base=,_name, _restore
        \\{
            _segsize _name\\#.size, ($)
            _context = (_context - (_base))
            org (_base + ($))
        \\}
        restore _restore
    \}
    match,_missed \{ end _continue \}
}

struc string data*&
{
    .: db data
    .sizeof = ($ - .)
}

macro enum [item*]
{
common
    local _start, _first, _item, _number
    _start = 0H
    _first = 1H
forward
    define _item item
    match _target =: _attribute, item
    \{
        define _item _target
        define _number
        match =&, _attribute
        \\{
            assert (~(_first))
            _start = ((_start) - 1H)
            define _number _
        \\}
        match,_number
        \\{
            assert ((_start) < (_attribute))
            _start = _attribute
        \\}
    \}
    match _, _item
    \{
        assert (~(definite (_)))
        _ = (_start)
    \}
    _start = ((_start) + 1H)
    _first = 0H
}

_VGA_BLACK = 0H
_VGA_BLUE = 1H
_VGA_GREEN = 2H
_VGA_CYAN = 3H
_VGA_RED = 4H
_VGA_MAGENTA = 5H
_VGA_BROWN = 6H
_VGA_LIGHT = 7H

_VGA_TEXT_ROW = 019H
_VGA_TEXT_COLUMN = 050H
_VGA_DIMENSION = (_VGA_TEXT_ROW * _VGA_TEXT_COLUMN)
_VGA_MEMORY_SIZE = (_VGA_DIMENSION * 2H)
_VGA_MEMORY_SEG = 0B800H

define _SCREEN_COUNT 4H
assert ((_SCREEN_COUNT > 0H) & (_SCREEN_COUNT < 00AH))

macro __screen_workspace _name*, _tss_kind*, _tss_param*&
{
    psegment _name
        .cached: db _VGA_MEMORY_SIZE dup 0H
        .cursor_flat: dd 0H
        .cursor_x: dd 0H
        .cursor_y: dd 0H
        .foreground: db _VGA_LIGHT
        .background: db _VGA_BLACK
        .attrsave: db 0H
        .cursor_state: db 1H
        psegment _name#_tss
            _tss_kind _tss_param
        end psegment
    end psegment
}

virtual at 0H
    __screen_workspace _generic_screen_workspace_16, TSS_16, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H
end virtual

virtual at 0H
    __screen_workspace _generic_screen_workspace_32, TSS_32, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H
end virtual

_GRUB_MAGIC = 01BADB002H
_GRUB_FLAGS = 0H
macro __grub_multiboot
{
    segment executable writable readable
    dd _GRUB_MAGIC
    dd _GRUB_FLAGS
    dd (-(_GRUB_MAGIC + _GRUB_FLAGS))
}

_STACK_BOTTOM = (1H shl 010H)
macro __declare_stack _name*
{
    psegment _name
        db _STACK_BOTTOM dup 0H
        .bottom:
    end psegment
}

__grub_multiboot

psegment _kernel_elf_entry
        cli 
        cld
        mov esi, _GDT
        mov edi, _GDT_BASE_ADDRESS
        mov ecx, ((_GDT.size + 1H) shr 2H)
        rep movsd
        mov ebp, esp
        push _GDT_BASE_ADDRESS
        pushw _GDT.size
        lgdt fword [esp]
        mov esp, ebp
        push _IDT
        pushw _IDT.size
        lidt fword [esp]
        mov ax, _tss_screen_segment_0.selector
        ltr ax
        mov ax, _ldt_screen_segment_0.selector
        lldt ax
        mov ax, _kernel_stack_segment_0.selector
        mov ss, ax
        mov esp, _kernel_stack_0.bottom
        mov ax, _kernel_data_segment.selector
        mov ds, ax
        jmp far _kernel_code_segment.selector : _kernel_code.init
end psegment

psegment _kernel_code
    .init:
        mov ax, _null_segment.selector
        mov ds, ax
        mov es, ax
        mov fs, ax
        mov gs, ax

    define _INTEL_RESERVED_INT 020H

        mov al, _INTEL_RESERVED_INT
        call .pic_remap
        call .init_keyboard
        call .disable_vga_cursor
        jmp .task_entry

    _IBM_PIC_MASTER_COMMAND = 020H
    _IBM_PIC_MASTER_DATA = (_IBM_PIC_MASTER_COMMAND + 1H)

    _IBM_PIC_SLAVE_COMMAND = 0A0H
    _IBM_PIC_SLAVE_DATA = (_IBM_PIC_SLAVE_COMMAND + 1H)

    _IBM_PIC_PIT = 0H
    _IBM_PIC_KEYBOARD = 1H
    _IBM_PIC_EOI = 020H

    define _IBM_PIC_HANDLE_INT 8H

    _8259_ICW1_ICW4 = 1B
    _8259_ICW1_SINGLE = 010B
    _8259_ICW1_INTERVAL_4 = 100B
    _8259_ICW1_LEVEL = 01000B
    _8259_ICW1_ALWAYS = 10000B

    _8259_ICW4_86_88 = 1B
    _8259_ICW4_AUTO_EOI = 010B
    _8259_ICW4_BUFFER_MODE_SLAVE = 01000B
    _8259_ICW4_BUFFER_MODE_MATSER = 01100B
    _8259_ICW4_SPECIAL_NESTED = 10000B

    .pic_remap:
        mov bl, al
        in al, _IBM_PIC_MASTER_DATA
        mov cl, al
        in al, _IBM_PIC_SLAVE_DATA
        mov dl, al
        mov al, _8259_ICW1_ALWAYS or _8259_ICW1_ICW4
        out _IBM_PIC_MASTER_COMMAND, al
        out _IBM_PIC_SLAVE_COMMAND, al
        mov al, bl
        and al, not 011B
        out _IBM_PIC_MASTER_DATA, al
        add al, _IBM_PIC_HANDLE_INT
        out _IBM_PIC_SLAVE_DATA, al
        mov al, 000000100B
        out _IBM_PIC_MASTER_DATA, al
        mov al, 010B
        out _IBM_PIC_SLAVE_DATA, al
        mov al, _8259_ICW4_86_88
        out _IBM_PIC_MASTER_DATA, al
        out _IBM_PIC_SLAVE_DATA, al
        mov al, cl
        out _IBM_PIC_MASTER_DATA, al    
        mov al, dl
        out _IBM_PIC_SLAVE_DATA, al
        ret

    .init_keyboard:
        call ._keyboard_control_wait_input_empty
        mov al, _KEYBOARD_CONTROL_ENABLE_KEYBOARD
        out _KEYBOARD_CONTROL, al
        call ._keyboard_control_wait_input_empty
        mov al, _KEYBOARD_ENCODER_ENABLE_KEYBOARD
        out _KEYBOARD_ENCODER, al
        call ._keyboard_control_wait_input_empty
        mov al, _KEYBOARD_ENCODER_SET_SCAN_CODE
        out _KEYBOARD_ENCODER, al
        call ._keyboard_control_wait_input_empty
        mov al, _XT_SCAN_CODE
        out _KEYBOARD_ENCODER, al
        ret

    .disable_vga_cursor:
        mov al, 00AH
        mov dx, 3D4H
        out dx, al
        mov al, 020H
        mov dx, 3D5H
        out dx, al
        ret

    .task_entry:
        sti
        call far _refresh_screen_gate.selector : 0H
        push _user_stack_segment_0.selector + _RPL3
        push _user_stack_0.bottom
        push _user_code_segment.selector + _RPL3
        push _user_code.start
        retfd

    .transform_flat:
      ; eax - the future x position
      ; ebx - the future y position
        push ebx
        cmp eax, _VGA_TEXT_COLUMN
        jae .transform_flat_error
        cmp ebx, _VGA_TEXT_ROW
        jae .transform_flat_error
        imul ebx, _VGA_TEXT_COLUMN
        jc .transform_flat_error
        add eax, ebx
        shl eax, 1H
        clc
        jmp .transform_flat_exit
    .transform_flat_error:
        stc
    .transform_flat_exit:
        pop ebx
        ret

    irp kind*, foreground,background
    {
        .set_#kind:
          ; set foreground/background - system call
          ; [esp+008H] - the target foreground/background color
            mov al, byte [esp+008H]
            cmp al, _VGA_LIGHT
            ja .set_#kind#_carry
            pushw ds _screen_segment_kernel_0.selector
            popw ds
            mov byte [_generic_screen_workspace_32.#kind], al
            popw ds
            clc
            jmp $+3H
        .set_#kind#_carry:
            stc
            retfd 4H
    }

    .set_cursor_position:
      ; set cursor - system call
      ; [esp+008H] - the future x position
      ; [esp+00CH] - the future y position
        mov eax, dword [esp+008H]
        mov ebx, dword [esp+00CH]
        mov ecx, eax
        call .transform_flat
        jc .set_cursor_position_exit
        pushw ds _screen_segment_kernel_0.selector
        popw ds
        call .hide_cursor
        lea eax, [_generic_screen_workspace_32.cached+eax]
        mov dword [_generic_screen_workspace_32.cursor_flat], eax
        mov dword [_generic_screen_workspace_32.cursor_x], ecx
        mov dword [_generic_screen_workspace_32.cursor_y], ebx
        call .show_cursor
        call far _kernel_code_segment.selector : .refresh_screen
        popw ds
    .set_cursor_position_exit:
        retfd 8H

    .get_cursor_position:
      ; get cursor - system call
        pushw ds _screen_segment_kernel_0.selector
        popw ds
        mov eax, dword [_generic_screen_workspace_32.cursor_x]
        mov ebx, dword [_generic_screen_workspace_32.cursor_y]
        popw ds
        retfd 0H

    _INVISIBLE_CURSOR = 0H
    .invisible_cursor:
      ; invisible cursor - system call
        pushw ds _screen_segment_kernel_0.selector
        popw ds
        call .hide_cursor
        mov byte [_generic_screen_workspace_32.cursor_state], _INVISIBLE_CURSOR
        call far _kernel_code_segment.selector : .refresh_screen
        popw ds
        retfd 0H

    _SOLID_CURSOR = 1H
    .solid_cursor:
      ; solid cursor - system call
        pushw ds _screen_segment_kernel_0.selector
        popw ds
        mov byte [_generic_screen_workspace_32.cursor_state], _SOLID_CURSOR
        call .show_cursor
        call far _kernel_code_segment.selector : .refresh_screen
        popw ds
        retfd 0H

    .worth_consider_cursor:
        cmp byte [_generic_screen_workspace_32.cursor_state], _INVISIBLE_CURSOR
        jz @f
        cmp dword [_generic_screen_workspace_32.cursor_x], _DISPLAY_LINE_EOF
    @@:
        ret

    .show_cursor:
        call .worth_consider_cursor
        jz .hide_cursor_exit
        push eax ebx edi
        mov edi, dword [_generic_screen_workspace_32.cursor_flat]
        mov al, byte [edi+1H]
        and al, 077H
        mov bl, al
        and bl, 00FH
        mov byte [_generic_screen_workspace_32.attrsave], al
        shr al, 4H
        cmp al, _VGA_LIGHT
        jnz @f
        mov al, (_VGA_BLACK shl 4H)
        cmp bl, _VGA_BLACK
        jnz .show_cursor_set
        mov bl, _VGA_LIGHT
        jmp .show_cursor_set
    @@:
        mov al, (_VGA_LIGHT shl 4H)
        cmp bl, _VGA_LIGHT
        jnz .show_cursor_set
        mov bl, _VGA_BLACK
    .show_cursor_set:
        or al, bl
        and byte [edi+1H], not 077H
        or byte [edi+1H], al
        pop edi ebx eax
    .show_cursor_exit:
        ret

    .hide_cursor:
        call .worth_consider_cursor
        jz .hide_cursor_exit
        push eax edi
        mov edi, dword [_generic_screen_workspace_32.cursor_flat]
        mov al, byte [_generic_screen_workspace_32.attrsave]
        mov byte [edi+1H], al
        pop edi eax
    .hide_cursor_exit:
        ret

    _SCROLL_UP = 0H
    _SCROLL_DOWN = 1H
    _SCROLL_LEFT = 2H
    _SCROLL_RIGHT = 3H

    .scroll:
      ; scroll - system call
      ; [esp+008H] - kind of scroll
      ; [esp+00CH] - line to scroll
      ; [esp+010H] - auto complete dimension
      ; [esp+014H] - upper row number
      ; [esp+018H] - left column number
      ; [esp+01CH] - lower row number
      ; [esp+020H] - right column number
        cmp dword [esp+00CH], 0H
        jz .scroll_exit
        push ebp
        mov ebp, esp
        xor eax, eax
        xor ebx, ebx
        mov ecx, (_VGA_TEXT_ROW - 1H)
        mov edx, (_VGA_TEXT_COLUMN - 1H)
        cmp dword [ebp+00CH], _SCROLL_RIGHT
        ja .scroll_exit
        cmp dword [esp+014H], 0H
        jnz .scroll_compute
        mov eax, dword [esp+018H]
        mov ebx, dword [esp+01CH]
        mov ecx, dword [esp+020H]
        mov edx, dword [esp+024H]
    .scroll_compute:
        mov edi, ecx
        cmp edi, _VGA_TEXT_ROW
        jae .scroll_exit
        sub edi, eax
        jb .scroll_exit
        mov esi, edx
        cmp esi, _VGA_TEXT_COLUMN
        jae .scroll_exit
        sub esi, ebx
        jb .scroll_exit
        cmp dword [ebp+00CH], _SCROLL_DOWN
        jnz $+4H
        add ebx, edi
        pushw ds es
        inc esi
        inc edi
        push esi edi
    .scroll_perform:
        pushw _screen_segment_kernel_0.selector _screen_segment_kernel_0.selector
        popw ds es
        call .hide_cursor
    @@:
        cmp dword [esp], 0H
        jz .scroll_write_screen
        push eax ebx ecx edx
        mov esi, dword [ebp+00CH]
        cmp esi, _SCROLL_RIGHT
        jnz $+3H
        xchg eax, edx
        call .transform_flat
        jc .scroll_write_screen
        lea edi, [_generic_screen_workspace_32.cached+eax]
        mov eax, dword [esp+00CH]
        mov edx, dword [esp]
        jmp dword [cs:_kernel_code.scroll_table+esi*4H]
    .scroll_continue:
        pop edx ecx ebx eax
        cmp dword [ebp+00CH], _SCROLL_DOWN
        jnz $+5H
        dec ebx
        jmp $+3H
        inc ebx
        dec dword [esp]
        jmp @b
    .scroll_write_screen:
        call .show_cursor
        call far _kernel_code_segment.selector : .refresh_screen
        add esp, 8H
        popw es ds
    .scroll_exit:
        leave
        retfd 01CH

    .scroll_up:
        add ebx, dword [ebp+010H]
        cmp ebx, ecx
        mov ecx, dword [esp+014H]
        ja .scroll_horizontal_clear
        call .transform_flat
        jc .scroll_horizontal_clear
        lea esi, [_generic_screen_workspace_32.cached+eax]
        rep movsw
        jmp .scroll_continue

    .scroll_down:
        mov ecx, dword [esp+014H]
        sub ebx, dword [ebp+010H]
        cmp ebx, eax
        jb .scroll_horizontal_clear
        call .transform_flat
        jc .scroll_horizontal_clear
        lea esi, [_generic_screen_workspace_32.cached+eax]
        rep movsw
        jmp .scroll_continue

    .scroll_left:
        mov ecx, dword [esp+014H]
        add eax, dword [ebp+010H]
        cmp eax, edx
        ja .scroll_horizontal_clear
        push eax
        call .transform_flat
        pop ebx
        jc .scroll_horizontal_clear
        lea esi, [_generic_screen_workspace_32.cached+eax]
        sub edx, ebx
        inc edx
        sub ecx, edx
        xchg ecx, edx
        rep movsw
        mov ecx, edx
        jmp .scroll_horizontal_clear

    .scroll_right:
        std
        mov ecx, dword [esp+014H]
        sub edx, dword [ebp+010H]
        cmp edx, eax
        jb .scroll_horizontal_clear
        push eax
        mov eax, edx
        call .transform_flat
        pop ebx
        jc .scroll_horizontal_clear
        lea esi, [_generic_screen_workspace_32.cached+eax]
        sub edx, ebx
        inc edx
        sub ecx, edx
        xchg ecx, edx
        rep movsw
        mov ecx, edx
        jmp .scroll_horizontal_clear
    
    .scroll_horizontal_clear:
        xor ax, ax
        call .adjust_color
        rep stosw
        cld
        jmp .scroll_continue

    .scroll_table:
        dd _kernel_code.scroll_up
        dd _kernel_code.scroll_down
        dd _kernel_code.scroll_left
        dd _kernel_code.scroll_right

    _DISPLAY_LINE_EOF = not 0H
    .display_string:
      ; display string - system call
      ; [esp+008H] - selector of the target string
      ; [esp+00CH] - offset of the target string
      ; [esp+010H] - size of the target string
        pushw ds es
        xor eax, eax
        mov ecx, dword [esp+014H]
        test ecx, ecx
        jz .display_string_exit
        mov esi, dword [esp+010H]
        pushw _screen_segment_kernel_0.selector
        popw ds
        mov edi, dword [_generic_screen_workspace_32.cursor_flat]
        mov ax, word [esp+008H]
        mov dx, word [esp+00CH]
        arpl dx, ax
        verr dx
        jnz .display_string_exit
        lsl eax, dx
        inc eax
        sub eax, esi
        jbe .display_string_exit
        cmp eax, ecx
        cmovb ecx, eax
        mov ebx, ecx
        call .adjust_color
        call .hide_cursor
        mov ds, dx
        pushw _screen_segment_kernel_0.selector
        popw es
    @@:
        cmp dword [es:_generic_screen_workspace_32.cursor_x], _VGA_TEXT_COLUMN
        jae .display_string_restore
        lodsb
        stosw
        inc dword [es:_generic_screen_workspace_32.cursor_x]
        loop @b
    .display_string_restore:
        pushw es
        popw ds
        mov dword [_generic_screen_workspace_32.cursor_flat], edi
        cmp dword [es:_generic_screen_workspace_32.cursor_x], _VGA_TEXT_COLUMN
        jz .display_string_overflow
        call .show_cursor
        jmp .display_string_sanitize
    .display_string_overflow:
        mov dword [_generic_screen_workspace_32.cursor_x], _DISPLAY_LINE_EOF
    .display_string_sanitize:
        mov eax, ebx
        sub eax, ecx
        call far _kernel_code_segment.selector : .refresh_screen
    .display_string_exit:
        popw es ds
        retfd 00CH

    .adjust_color:
        mov ah, byte [_generic_screen_workspace_32.background]
        shl ah, 4H
        or ah, [_generic_screen_workspace_32.foreground]
        ret

    .refresh_screen:
      ; refresh screen - system call
        pushw ds es _screen_segment_kernel_0.selector _video_segment.selector
        popw es ds
        mov esi, _generic_screen_workspace_32.cached
        xor edi, edi
        mov ecx, (_VGA_MEMORY_SIZE shr 2H)
        rep movsd
        mov ecx, ((_VGA_MEMORY_SIZE shr 1H) and 1B)
        rep movsw
        popw es ds
        retfd 0H

    .atoi:
      ; alpha to integer - system call
      ; [esp+008H] - selector of target buffer
      ; [esp+00CH] - offset of target buffer
      ; [esp+010H] - size of the target buffer
        pushw ds
        mov ax, word [esp+6H]
        mov dx, word [esp+00AH]
        arpl dx, ax
        verr dx
        jnz .atoi_carry
        lsl ecx, dx
        inc ecx
        mov esi, dword [esp+00EH]
        sub ecx, esi
        jbe .atoi_carry
        mov eax, dword [esp+012H]
        cmp ecx, eax
        cmova ecx, eax
        jecxz .atoi_exit
        mov ds, dx
        xor ebx, ebx
        xor edx, edx
        xor eax, eax
    .atoi_loop:
        lodsb
        sub al, 030H
        jc .atoi_next
        cmp al, 9H
        jbe .atoi_compute
        or al, 020H
        sub al, 031H
        jc .atoi_next
        cmp al, 05H
        ja .atoi_next
        add al, 00AH
    .atoi_compute:
        shl ebx, 4H
        add ebx, eax   
        jc .atoi_carry
        mov dl, 1H
        loop .atoi_loop
    .atoi_next:
        test dl, dl
        jz .atoi_carry
        mov eax, ebx
        lea edi, [esi-1H]
        clc
        jmp .atoi_exit
    .atoi_carry:
        stc
    .atoi_exit:
        popw ds
        retfd 00CH
    
    _PADDING_MAX = 8H
    .itoa:
      ; integer to alpha - system call
      ; [esp+008H] - target number
      ; [esp+00CH] - selector of target buffer
      ; [esp+010H] - offset of target buffer
      ; [esp+014H] - padding of zero for the resulting string
      ; [esp+018H] - size of target buffer
        xor eax, eax
        cmp dword [esp+014H], _PADDING_MAX
        jbe @f
        mov dword [esp+014H], _PADDING_MAX
    @@:
        mov ecx, dword [esp+018H]
        jecxz .itoa_exit
        mov edi, dword [esp+010H]
        mov bx, word [esp+4H]
        mov dx, word [esp+00CH]
        arpl dx, bx
        verw dx
        jnz .itoa_exit
        lsl ebx, dx
        inc ebx
        sub ebx, edi
        jbe .itoa_exit
        pushw ds es
        cmp ebx, ecx
        cmovb ecx, ebx
        mov es, dx
        mov ebx, .itoa_table
        mov eax, dword [esp+00CH]
        push ebp
        mov ebp, esp
        mov esi, 010H
    .itoa_loop:
        xor edx, edx
        div esi
        xchg eax, edx
        cs xlatb
        dec esp
        mov byte [esp], al
        test edx, edx
        xchg edx, eax
        jnz .itoa_loop
        mov eax, ebp
        sub eax, esp
        mov edx, dword [ebp+01CH]
        cmp eax, edx
        jae .itoa_write
        sub edx, eax
        add eax, edx
        xchg ecx, edx
    @@:
        dec esp
        mov byte [esp], 030H
        loop @b
        mov ecx, edx
    .itoa_write:
        cmp ecx, eax
        cmova ecx, eax
        mov eax, ecx
        mov esi, esp
        pushw ss
        popw ds
        rep movsb
        leave
        popw es ds
    .itoa_exit:
        retfd 014H
    .itoa_table: db "0123456789ABCDEF"

    .switch_screen:
      ; switch screen - system call
      ; [esp+8H] - target screen
        mov ax, word [esp+8H]
        cmp ax, _SCREEN_COUNT
        jae .switch_screen_carry
        shl ax, 4H
        add ax, _tss_screen_segment_0.selector
        str bx
        cmp ax, bx
        jz .switch_screen_carry
        pushw ax
        pushd 0H
        jmp far [esp]
        add esp, 6H
        call far _kernel_code_segment.selector : .refresh_screen
        clc
        jmp $+3H
    .switch_screen_carry:   
        stc
        retfd 4H

    .retreive_screen:
        str eax
        sub ax, _tss_screen_segment_0.selector
        shr ax, 4H
        retfd 0H

    .read_keyboard:
      ; read keyboard - system call
      ; [esp+008H] - selector of target buffer
      ; [esp+00CH] - offset of target buffer
      ; [esp+010H] - size of target buffer
        mov ax, word [esp+004H]
        mov dx, word [esp+008H]
        arpl dx, ax
        verw dx
        jnz .read_keyboard_exit
        lsl eax, dx
        inc eax
        mov edi, dword [esp+00CH]
        mov esi, _kernel_data._keyboard_buffer
        xor ecx, ecx
        sub eax, edi
        cmovbe eax, ecx
        jbe .read_keyboard_exit
        mov ecx, dword [esp+010H]
        cmp eax, ecx
        cmova eax, ecx
        cli
        pushw es ds
        mov es, dx
        mov dx, _kernel_data_segment.selector
        mov ds, dx
        mov ecx, dword [_kernel_data._keyboard_index]
        cmp eax, ecx
        cmova eax, ecx
        mov ecx, eax
        jecxz .read_keyboard_reenable
        rep movsb
        pushw ds
        popw es
        mov edi, _kernel_data._keyboard_buffer
        lea esi, [edi+eax]
        sub dword [_kernel_data._keyboard_index], eax
        mov ecx, dword [_kernel_data._keyboard_index]
        shr ecx, 2H
        inc ecx
        rep movsd
    .read_keyboard_reenable:
        popw ds es
        sti
    .read_keyboard_exit:
        retfd 00CH

    .reboot:
        cmp dword [esp+8H], 0DEADC0DEH
        jnz .reboot_exit
        pushd 0H
        pushw 0H
        lidt fword [esp]
        ud2
;       call ._keyboard_control_wait_input_empty
;       mov al, 0D1H
;       out _KEYBOARD_CONTROL, al
;       call ._keyboard_control_wait_input_empty
;       mov al, 0FEH
;       out _KEYBOARD_ENCODER, al
    .reboot_exit:
        retfd 4H

    .shutdown:
        cmp dword [esp+8H], 0DEEDFADEH
        jnz .shutdown_exit
        pushw _kernel_data_segment.selector
        popw ds
        mov esi, _kernel_data.shutdown_payload
        mov ecx, _kernel_data.shutdown_payload.sizeof
        call .jump_unreal
    .shutdown_exit:
        retfd 4H

    _START_UNREAL = 07C00H
    _STACK_UNREAL = 06F00H
    virtual at _START_UNREAL
        use16
        ._unreal::
        ._unreal.base = $$
            mov eax, cr0
            and al, not 1H
            mov cr0, eax
            jmp 0H : ._unreal_reset ; reset the so-called prefetch queue ;)
        ._unreal_reset:
            xor ax, ax
            mov ds, ax
            mov ss, ax
            mov es, ax
            mov sp, _STACK_UNREAL
        ._unreal.sizeof = ($ - ._unreal.base)
    end virtual
    use32

    .jump_unreal:
        cli
        mov ax, _unreal_data_segment.selector
        mov es, ax
        mov edi, _START_UNREAL
        repeat ._unreal.sizeof
            load _ byte from ._unreal:(((%) - 1H) + ._unreal.base)
            mov al, _
            stosb
        end repeat
        rep movsb
        mov ax, 0FEEBH ; jmp $
        stosw
        pushw es
        popw ds
        push _unreal_idt
        pushw _unreal_idt.size
        lidt fword [esp]
        jmp far _unreal_code_segment.selector : _START_UNREAL
        ret

    .unreal_realm:
        pushw _kernel_data_segment.selector
        popw ds
        mov esi, _kernel_data.unreal_realm_payload
        mov ecx, _kernel_data.unreal_realm_payload.sizeof
        call .jump_unreal
        ret

    rept (_INTEL_RESERVED_INT + (_IBM_PIC_HANDLE_INT * 2H)) i:0H
    {
        ._handler_#i:
            pushd i
            jmp .int_handler
    }
    
    .int_handler:
        pushad
        pushw ds es fs gs
        mov ax, _kernel_data_segment.selector
        mov ds, ax
        movzx ebx, byte [esp+8H+020H]
        cmp bl, _INTEL_RESERVED_INT
        cmp bl, (_INTEL_RESERVED_INT + _IBM_PIC_KEYBOARD)
        jnz .int_handler_next
        call .keyboard_driver
    .int_handler_next:
        cmp bl, _INTEL_RESERVED_INT
        jb .int_handler_exit
        mov al, _IBM_PIC_EOI
        out _IBM_PIC_MASTER_COMMAND, al
        cmp bl, (_INTEL_RESERVED_INT + _IBM_PIC_HANDLE_INT)
        jb .int_handler_exit
        out _IBM_PIC_SLAVE_COMMAND, al
    .int_handler_exit:
        popw gs fs es ds
        popad
        add esp, 4H
        iretd

    _KEYBOARD_CONTROL = 064H
    _KEYBOARD_ENCODER = 060H

    _KEYBOARD_CONTROL_STATUS_OUT = 1B
    _KEYBOARD_CONTROL_STATUS_IN = 010B
 
    _KEYBOARD_CONTROL_READ_COMMAND = 020H
    _KEYBOARD_CONTROL_ENABLE_KEYBOARD = 0AEH   

    _KEYBOARD_ENCODER_ENABLE_KEYBOARD = 0F4H
    _KEYBOARD_ENCODER_SET_SCAN_CODE = 0F0H

    _XT_SCAN_CODE = 2H

    enum    _KEY_NULL, _KEY_ESC, _KEY_1, _KEY_2, _KEY_3, _KEY_4, _KEY_5, _KEY_6, _KEY_7, _KEY_8, _KEY_9, _KEY_0,\
            _KEY_MINUS, _KEY_EQUAL, _KEY_BACKSPACE, _KEY_TAB, _KEY_Q, _KEY_W, _KEY_E, _KEY_R, _KEY_T, _KEY_Y,\
            _KEY_U, _KEY_I, _KEY_O, _KEY_P, _KEY_LEFT_BRACK, _KEY_RIGHT_BRACK, _KEY_ENTER, _KEY_KEYPAD_ENTER:&,\
            _KEY_LEFT_CTRL, _KEY_RIGHT_CTRL:&, _KEY_A, _KEY_S, _KEY_D, _KEY_F, _KEY_G, _KEY_H, _KEY_J, _KEY_K, _KEY_L,\
            _KEY_SEMICOLON, _KEY_QUOTE, _KEY_BACK_TICK, _KEY_LEFT_SHIFT, _KEY_PRINT_SCREEN_1:&, _KEY_BACKSLASH,\
            _KEY_Z, _KEY_X, _KEY_C, _KEY_V, _KEY_B, _KEY_N, _KEY_M, _KEY_COMMA, _KEY_DOT, _KEY_SLASH, _KEY_KEYPAD_SLASH:&,\
            _KEY_RIGHT_SHIFT, _KEY_KEYPAD_STAR, _KEY_PRINT_SCREEN_2:&, _KEY_LEFT_ALT, _KEY_RIGHT_ALT:&, _KEY_SPACE,\
            _KEY_CAPS_LOCK, _KEY_F1, _KEY_F2, _KEY_F3, _KEY_F4, _KEY_F5, _KEY_F6, _KEY_F7, _KEY_F8, _KEY_F9, _KEY_F10,\
            _KEY_KEYPAD_NUM_LOCK, _KEY_SCROLL_LOCK, _KEY_HOME, _KEY_KEYPAD_7:&, _KEY_UP_ARROW, _KEY_KEYPAD_8:&, _KEY_PAGE_UP,\
            _KEY_KEYPAD_9:&, _KEY_KEYPAD_MINUS, _KEY_LEFT_ARROW, _KEY_KEYPAD_4:&, _KEY_KEYPAD_5, _KEY_RIGHT_ARROW,\
            _KEY_KEYPAD_6:&, _KEY_KEYPAD_PLUS, _KEY_END, _KEY_KEYPAD_1:&, _KEY_DOWN_ARROW, _KEY_KEYPAD_2:&, _KEY_PAGE_DOWN,\
            _KEY_KEYPAD_3:&, _KEY_INSERT, _KEY_KEYPAD_0:&, _KEY_DELETE, _KEY_KEYPAD_DOT:&, _KEY_F11:057H, _KEY_F12,\
            _KEY_LEFT_GUI:05BH, _KEY_RIGHT_GUI, _KEY_APPS, _KEY_PAUSE_1:0451DH ; XXX _KEY_PAUSE_2

    _BREAK_CODE = 080H
    _EXTENDED_1_CODE = 0E0H
    _EXTENDED_2_CODE = 0E1H
    _CTRL_MASK = 080H
    _MAJ_MASK = 020H
    
    ; Special keypress are "escaped" like in UN*X
    enum    _ESC_ESC, _ESC_LEFT_ARROW, _ESC_RIGHT_ARROW, _ESC_UP_ARROW, _ESC_DOWN_ARROW,\
            _ESC_GUI, _ESC_F1, _ESC_F2, _ESC_F3, _ESC_F4, _ESC_F5, _ESC_F6, _ESC_F7,\
            _ESC_F8, _ESC_F9, _ESC_F10, _ESC_F11, _ESC_F12

    ._keyboard_control_wait_output_full:
        in al, _KEYBOARD_CONTROL
        test al, _KEYBOARD_CONTROL_STATUS_OUT
        jz ._keyboard_control_wait_output_full
        ret

    ._keyboard_control_wait_input_empty:
        in al, _KEYBOARD_CONTROL
        test al, _KEYBOARD_CONTROL_STATUS_IN
        jnz ._keyboard_control_wait_input_empty
        ret
  
    .keyboard_driver:
        push ebx
        call .keyboard_driver_scan_code
        mov dl, 0FFH
        cmp al, _EXTENDED_1_CODE
        jz .keyboard_driver_extended_1
        cmp al, _EXTENDED_2_CODE
        jz .keyboard_driver_extended_2
        test al, _BREAK_CODE
        jz @f
        inc dl
        xor al, _BREAK_CODE
    @@:
        cmp byte [_kernel_data._keyboard_extended_1], 1H
        jz .keyboard_driver_handle_extended_1
        cmp byte [_kernel_data._keyboard_extended_2], 0H
        jnz .keyboard_driver_handle_extended_2
        jmp .keyboard_driver_make_code
    .keyboard_driver_extended_1:
        mov byte [_kernel_data._keyboard_extended_1], 1H
        jmp .keyboard_driver_exit
    .keyboard_driver_extended_2:
        mov byte [_kernel_data._keyboard_extended_1], 2H
        jmp .keyboard_driver_exit
    .keyboard_driver_handle_extended_1:
        cmp al, _KEY_RIGHT_CTRL
        mov ebx, _kernel_data._keyboard_right_ctrl
        jz .keyboard_driver_save_state
        cmp al, _KEY_RIGHT_ALT
        mov ebx, _kernel_data._keyboard_right_alt
        jz .keyboard_driver_save_state
        test dl, dl
        jz .keyboard_decrease_extended
    irp value*, LEFT_ARROW,RIGHT_ARROW,UP_ARROW,DOWN_ARROW
    {
        cmp al, _KEY_#value
        mov bl, _ESC_#value
        jz .keyboard_driver_insert_escape
    }
        cmp al, _KEY_LEFT_GUI
        mov bl, _ESC_GUI
        jz .keyboard_driver_insert_escape
        cmp al, _KEY_RIGHT_GUI
        jz .keyboard_driver_insert_escape
        cmp byte [_kernel_data._keyboard_num_lock], 0H
        jz  .keyboard_decrease_extended
        cmp al, _KEY_KEYPAD_SLASH
        jz .keyboard_driver_insert
        cmp al, _KEY_KEYPAD_ENTER
        jz .keyboard_driver_insert
        jmp .keyboard_decrease_extended        
    .keyboard_driver_handle_extended_2:
        jmp .keyboard_decrease_extended
    .keyboard_driver_insert_escape:
        mov ecx, dword [_kernel_data._keyboard_index]
        cmp ecx, (_INTERNAL_KEYBOARD_BUFFER_SIZE - 1H)
        jae .keyboard_decrease_extended
        shl bx, 8H
        or bl, 01BH
        mov word [_kernel_data._keyboard_buffer+ecx], bx
        add dword [_kernel_data._keyboard_index], 2H
        jmp .keyboard_decrease_extended
    .keyboard_driver_make_code:
        cmp al, _KEY_LEFT_CTRL
        mov ebx, _kernel_data._keyboard_left_ctrl    
        jz .keyboard_driver_save_state
        cmp al, _KEY_LEFT_SHIFT
        mov ebx, _kernel_data._keyboard_left_shift
        jz .keyboard_driver_save_state
        cmp al, _KEY_RIGHT_SHIFT
        mov ebx, _kernel_data._keyboard_right_shift
        jz .keyboard_driver_save_state
        cmp al, _KEY_LEFT_ALT
        mov ebx, _kernel_data._keyboard_right_alt
        jz .keyboard_driver_save_state
        test dl, dl
        jz .keyboard_driver_exit
        cmp al, _KEY_CAPS_LOCK
        mov ebx, _kernel_data._keyboard_caps_lock
        jz .keyboard_driver_invert_state
        cmp al, _KEY_KEYPAD_NUM_LOCK
        mov ebx, _kernel_data._keyboard_num_lock
        jz .keyboard_driver_invert_state 
    irp value*, ESC,F1,F2,F3,F4,F5,F6,F7,F8,F9,F10,F11,F12
    {
        cmp al, _KEY_#value
        mov bl, _ESC_#value
        jz .keyboard_driver_insert_escape
    }
    .keyboard_driver_insert:
        mov ecx, dword [_kernel_data._keyboard_index]
        cmp ecx, _INTERNAL_KEYBOARD_BUFFER_SIZE
        jae .keyboard_driver_exit
    irp value*, 0,1,2,3,4,5,6,7,8,9,DOT,MINUS,PLUS,STAR
    {
        cmp al, _KEY_KEYPAD_#value
        jz .keyboard_driver_only_numlock
    }
        jmp .keyboard_driver_translate
    .keyboard_driver_only_numlock:
        cmp byte [_kernel_data._keyboard_num_lock], 0H
        jz .keyboard_driver_exit
    .keyboard_driver_translate:
        mov ebx, _kernel_code._translation_table
        cs xlatb
        call .keyboard_driver_shift_pressed
        jz .keyboard_driver_case_update
    irp value*, 060H,031H,032H,033H,034H,035H,036H,037H,038H,039H,030H,02DH,03DH,05BH,05DH,05CH,03BH,027H,02CH,02EH,02FH
    {
        cmp al, value
        match =060H, value \{ mov bx, 07EH \}
        match =031H, value \{ mov bx, 021H \}
        match =032H, value \{ mov bx, 040H \}
        match =033H, value \{ mov bx, 023H \}
        match =034H, value \{ mov bx, 024H \}
        match =035H, value \{ mov bx, 025H \}
        match =036H, value \{ mov bx, 05EH \}
        match =037H, value \{ mov bx, 026H \}
        match =038H, value \{ mov bx, 02AH \}
        match =039H, value \{ mov bx, 028H \}
        match =030H, value \{ mov bx, 029H \}
        match =02DH, value \{ mov bx, 05FH \}
        match =03DH, value \{ mov bx, 02BH \}
        match =05BH, value \{ mov bx, 07BH \}
        match =05DH, value \{ mov bx, 07DH \}
        match =05CH, value \{ mov bx, 07CH \}
        match =03BH, value \{ mov bx, 03AH \}
        match =027H, value \{ mov bx, 022H \}
        match =02CH, value \{ mov bx, 03CH \}
        match =02EH, value \{ mov bx, 03EH \}
        match =02FH, value \{ mov bx, 03FH \}
        cmovz ax, bx
        jz .keyboard_driver_write
    }
        jmp .keyboard_driver_case_convert
    .keyboard_driver_case_update:
        mov dl, byte [_kernel_data._keyboard_caps_lock]
        test dl, dl
        jz .keyboard_driver_write
    .keyboard_driver_case_convert:
        cmp al, 061H
        jb .keyboard_driver_write
        cmp al, 07AH
        ja .keyboard_driver_write
        and al, not _MAJ_MASK
    .keyboard_driver_write:
        call .keyboard_driver_ctrl_pressed
        jz $+4H
        or al, _CTRL_MASK
        test al, al
        jz .keyboard_driver_exit
        mov byte [_kernel_data._keyboard_buffer+ecx], al
        lock inc dword [_kernel_data._keyboard_index]
        jmp .keyboard_driver_exit
    .keyboard_decrease_extended:
        mov byte [_kernel_data._keyboard_extended_1], 0H
        movzx ecx, byte [_kernel_data._keyboard_extended_2]
        jecxz .keyboard_driver_exit
        dec ecx
        mov byte [_kernel_data._keyboard_extended_2], cl
    .keyboard_driver_exit:
        pop ebx
        ret
    .keyboard_driver_scan_code:
        call ._keyboard_control_wait_output_full
        in al, _KEYBOARD_ENCODER
        ret
    .keyboard_driver_save_state:
        mov byte [ebx], dl
        jmp .keyboard_decrease_extended
    .keyboard_driver_invert_state:
        not byte [ebx]
        jmp .keyboard_driver_exit
    .keyboard_driver_update_led:
        ; XXX
    irp kind*, ctrl,shift,alt
    {
        .keyboard_driver_#kind#_pressed:
            mov dl, byte [_kernel_data._keyboard_left_#kind]
            or dl, byte [_kernel_data._keyboard_right_#kind]
            test dl, dl
            ret
    }

    ._translation_table:
        db 000H, 01BH, 031H, 032H
        db 033H, 034H, 035H, 036H
        db 037H, 038H, 039H, 030H
        db 02DH, 03DH, 008H, 009H
        db 071H, 077H, 065H, 072H
        db 074H, 079H, 075H, 069H
        db 06FH, 070H, 05BH, 05DH
        db 00DH, 000H, 061H, 073H
        db 064H, 066H, 067H, 068H
        db 06AH, 06BH, 06CH, 03BH
        db 027H, 060H, 000H, 05CH
        db 07AH, 078H, 063H, 076H
        db 062H, 06EH, 06DH, 02CH
        db 02EH, 02FH, 000H, 02AH
        db 000H, 020H, 000H, 000H
        db 000H, 000H, 000H, 000H
        db 000H, 000H, 000H, 000H
        db 000H, 000H, 000H, 037H
        db 038H, 039H, 02DH, 034H
        db 035H, 036H, 02BH, 031H
        db 032H, 033H, 030H, 02EH
        times (0FFH - ($ - ._translation_table)) db 0H

    _LCG_A_ANSI_C = 041C64E6DH
    _LCG_C_ANSI_C = 03039H
    _LCG_MAX = 07FFFH
    .linear_congruencial_generator:
        pushw ds _kernel_data_segment.selector
        popw ds
        mov eax, dword [_kernel_data.lcg_next]
        mov ecx, _LCG_A_ANSI_C
        mul ecx
        add eax, _LCG_C_ANSI_C
        mov dword [_kernel_data.lcg_next], eax
        shr eax, 010H
        xor edx, edx
        mov ecx, (_LCG_MAX + 1H)
        div ecx
        mov eax, edx
        popw ds
        ret

    .cmatrix:
        pushw _cmatrix_screen_segment.selector _cmatrix_misc_segment.selector
        popw es ds
        mov byte [_cmatrix_screen.foreground], _VGA_GREEN
        call far _kernel_code_segment.selector : .invisible_cursor
    .cmatrix_next_task:
        push 0H 0H 0H 0H
        push 1H
        push _VGA_TEXT_COLUMN
        push _SCROLL_UP
        call far _kernel_code_segment.selector : .scroll
        xor ecx, ecx
    .cmatrix_loop:
        call .cmatrix_read
        jz @f
        cmp byte [es:_cmatrix_misc.character], 071H
        jz .cmatrix_exit
    @@:
        call .cmatrix_feed
        push _VGA_TEXT_COLUMN
        push _cmatrix_misc.random_line
        push _cmatrix_misc_segment.selector
        call far _kernel_code_segment.selector : .display_string
        call far _kernel_code_segment.selector : .get_cursor_position
        xor eax, eax
        inc ebx
        cmp ebx, _VGA_TEXT_ROW
        jb @f
        xor ebx, ebx
    @@:
        push ebx eax
        call far _kernel_code_segment.selector : .set_cursor_position
        jmp .cmatrix_loop
    .cmatrix_exit:
        iretd
        jmp .cmatrix_next_task
    .cmatrix_feed:
        mov edi, _cmatrix_misc.random_line
        mov ecx, _VGA_TEXT_COLUMN
    .cmatrix_feed_loop:
        push ecx
        call .linear_congruencial_generator
        pop ecx
        and eax, 0FFH
        call .cmatrix_ascii
        jc .cmatrix_feed_loop
        stosb
        loop .cmatrix_feed_loop
        ret
    .cmatrix_ascii:
        cmp al, 041H
        jc .cmatrix_ascii_exit
        cmp al, 05BH
        jc @f
        cmp al, 061H
        jc .cmatrix_ascii_exit
        cmp al, 07BH
    @@:
        cmc
    .cmatrix_ascii_exit:
        ret
    .cmatrix_read:
        push 1H
        push _cmatrix_misc.character
        push _cmatrix_misc_segment.selector
        call far _kernel_code_segment.selector : .read_keyboard
        test eax, eax
        ret
end psegment

psegment _kernel_data, use16
    _INTERNAL_KEYBOARD_BUFFER_SIZE = 400H
    assert ((~(_INTERNAL_KEYBOARD_BUFFER_SIZE and 011B)) & (_INTERNAL_KEYBOARD_BUFFER_SIZE))

    ._keyboard_buffer: db (_INTERNAL_KEYBOARD_BUFFER_SIZE + 4H) dup 0H
    ._keyboard_index: dd 0H

    ._keyboard_extended_1: db 0H
    ._keyboard_extended_2: db 0H
    ._keyboard_print_screen_begin: db 0H
    ._keyboard_pause_begin: db 0H
    ._keyboard_right_ctrl: db 0H
    ._keyboard_left_ctrl: db 0H
    ._keyboard_right_shift: db 0H
    ._keyboard_left_shift: db 0H
    ._keyboard_right_alt: db 0H
    ._keyboard_left_alt: db 0H
    ._keyboard_caps_lock: db 0H
    ._keyboard_num_lock: db 0H

    .unreal_realm_payload:
        call .unreal_realm_payload_start
        ._unreal_hello string "[<UNREAL MODE>]"
    .unreal_realm_payload_start:
        mov ax, 3H
        int 010H
        mov ax, 01301H
        mov bx, _VGA_LIGHT
        mov cx, ._unreal_hello.sizeof
        xor dx, dx
        mov bp, sp
        mov bp, word [bp]
        int 010H
    .unreal_realm_payload.sizeof = ($ - .unreal_realm_payload)

    .shutdown_payload:
        mov ax, 05307H
        mov bx, 1H
        mov cx, 3H
        int 015H
    .shutdown_payload.sizeof = ($ - .shutdown_payload)

    .lcg_next: dd 0FEEDH

    _DEFAULT_FLAGS = 202H ; IF & CPUID reserved
    rept _SCREEN_COUNT i:0H
    {
        __screen_workspace _kernel_screen_#i, TSS_32, 0H, _kernel_stack_0.bottom, _kernel_stack_segment_0.selector, 0H, 0H, 0H, 0H, 0H,\
            _kernel_code.task_entry, _DEFAULT_FLAGS, 0H, 0H, 0H, 0H, _kernel_stack_0.bottom, 0H, 0H, 0H, 0H, _kernel_code_segment.selector,\
            _kernel_stack_segment_0.selector, 0H, 0H, 0H, _ldt_screen_segment_#i#.selector, 0H, 0H
    }

    __screen_workspace _cmatrix_screen, TSS_32, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H,\
        _kernel_code.cmatrix, _DEFAULT_FLAGS, 0H, 0H, 0H, 0H, _cmatrix_stack.bottom, 0H, 0H, 0H, 0H, _kernel_code_segment.selector,\
        _cmatrix_stack_segment.selector, 0H, 0H, 0H, _ldt_cmatrix.selector, 0H, 0H

    psegment _cmatrix_misc
        .random_line: db _VGA_TEXT_COLUMN dup 0H
        .character: db 0H
    end psegment
end psegment

rept _SCREEN_COUNT i:0H { __declare_stack _kernel_stack_#i }
__declare_stack _cmatrix_stack

define _SIZE_HISTORY 010H
define _USER_COMMAND_SIZE (_VGA_TEXT_COLUMN * 2H)
define _BOTTOM_SCREEN_ROW (_VGA_TEXT_ROW - 1H)

assert ((_BOTTOM_SCREEN_ROW) & (_USER_COMMAND_SIZE))

macro align _power*, _padding:0H
{
    assert ((bsr (_power)) = (bsf (_power)))
    while ($ mod (_power))
        db (_padding)
    end while
}

struc __user_workspace
{
    ._buffer: db _USER_COMMAND_SIZE dup 0H
    ._length: dd 0H
    align 4H
}

virtual at 0H
    __user_workspace __user_workspace
    __user_workspace.sizeof = $
end virtual

psegment _user_code
        mov ax, _user_data_segment.selector
        mov fs, ax
        mov ax, _user_data_command_segment_0.selector
        mov ds, ax
        mov es, ax

;    @@:
;        call .read_one_character
;        jz @b
;        movzx eax, byte [_user_data_command_0._last]
;        push 010H
;        push 2H
;        push _user_data._resb
;        push _user_data_segment.selector
;        push eax
;        call far _itoa_gate.selector : 0H
;        push 2H
;        push _user_data._resb
;        push _user_data_segment.selector 
;        call far _display_string_gate.selector : 0H
;        mov eax, 1H
;        call .scroll_terminal
;        jmp @b

        call .display_bottom
        call .display_command
    .loop:
        call .read_one_character
        jz .loop 

        mov al, byte [_user_data_command_0._last]
        cmp al, 00DH
        jz .process_command
        cmp al, 8H
        jz .remove_character
        cmp al, 01BH
        jnz @f
        call .read_one_character
        cmp eax, _ESC_LEFT_ARROW
        mov ecx, .cursor_backward
        jz .execute_predicate
        cmp eax, _ESC_RIGHT_ARROW
        mov ecx, .cursor_forward
        jz .execute_predicate
        cmp eax, _ESC_UP_ARROW
        mov ecx, .move_up_history
        jz .execute_predicate
        cmp eax, _ESC_DOWN_ARROW
        mov ecx, .move_down_history
        jz .execute_predicate
        jmp .loop
    @@:
        mov al, byte [_user_data_command_0._last]
        and byte [_user_data_command_0._last], not _CTRL_MASK
        test al, _CTRL_MASK
        jz .save_character
        xor al, _CTRL_MASK
        mov bl, al

        cmp bl, 062H
        mov ecx, .switch_back
        jz .execute_predicate
        cmp bl, 06EH
        mov ecx, .switch_next
        jz .execute_predicate
        cmp bl, 06BH
        mov ecx, .command_truncate
        jz .execute_predicate
        cmp bl, 061H
        mov ecx, .begin_cursor
        jz .execute_predicate
        cmp bl, 065H
        mov ecx, .end_cursor
        jz .execute_predicate
        cmp bl, 076H
        jnz .save_character
        mov eax, _user_data_command_0._copy._buffer
        mov ebx, dword [_user_data_command_0._copy._length]
        jmp .insert_user_input
    .save_character:
        mov eax, _user_data_command_0._last
        mov ebx, 1H
    .insert_user_input:
        call .command_insert
    .update_line:
        call .display_command
        jmp .loop

    .execute_predicate:
        call ecx
        jmp .update_line
    .remove_character:
        call .command_remove
        jmp .loop

    .process_command:
        call .end_cursor
        call .display_command
        call .goto_next_line

        mov edi, _user_data_command_0._command._buffer
        mov ecx, dword [_user_data_command_0._command._length]
        call .skip_whitespace
        jz .validate_command

        irp kind*, help,copyright,clear,switch,cmatrix,fg,bg,unreal,copy,history,dump,find,register,reboot,shutdown
        {
            mov eax, _user_data._#kind#.sizeof
            mov ebx, .command_#kind
            mov esi, _user_data._#kind
            call .parse_command
            jnc .validate_command
        }

        call .command_unknown
    .validate_command:
        call .save_history
        call .retablish_shell
        jmp .loop

    .read_one_character:
        push 1H
        push _user_data_command_0._last
        push _user_data_command_segment_0.selector
        call _read_keyboard_gate.selector : 0H
        test eax, eax
        mov al, byte [_user_data_command_0._last]
        ret

    .command_shift:
        jecxz .command_shift_exit
        rep movsb
    .command_shift_exit:
        cld
        ret

    .command_insert:
        mov ecx, _USER_COMMAND_SIZE
        mov edx, dword [_user_data_command_0._command._length]
        sub ecx, edx
        jbe .command_insert_exit
        cmp ebx, ecx
        cmovb ecx, ebx
        jecxz .command_insert_exit
        lea esi, [_user_data_command_0._command._buffer+edx-1H]
        lea edi, [esi+ecx]
        push ecx
        mov ecx, dword [_user_data_command_0._cursor]
        sub edx, ecx
        xchg ecx, edx
        std
        call .command_shift
        mov ecx, dword [esp]
        add dword [_user_data_command_0._command._length], ecx
        mov esi, eax
        lea edi, [_user_data_command_0._command._buffer+edx]
        rep movsb
        call .display_command
        cmp dword [esp], (_VGA_TEXT_COLUMN)
        lahf
        mov ebx, dword [_user_data_command_0._cursor]
        add dword [esp], ebx
        sahf
        jbe @f
        call .end_cursor
    @@:
        pop ecx
        mov dword [_user_data_command_0._cursor], ecx
    .command_insert_exit:
        ret

    .command_remove:
        mov ecx, dword [_user_data_command_0._cursor]
        jecxz .command_remove_exit
        lea edi, [_user_data_command_0._command._buffer+ecx-1H]
        lea esi, [edi+1H]
        mov edx, dword [_user_data_command_0._command._length]
        mov ebx, edx
        xchg edx, ecx
        sub ecx, edx
        call .command_shift
        dec dword [_user_data_command_0._cursor]
        mov byte [_user_data_command_0._command._buffer+ebx-1H], 0H
        call .display_command
        dec dword [_user_data_command_0._command._length]
    .command_remove_exit: 
        ret

    .command_truncate:
        mov ecx, dword [_user_data_command_0._command._length]
        mov ebx, dword [_user_data_command_0._cursor]
        sub ecx, ebx
        jz .command_truncate_exit
        lea edi, [_user_data_command_0._command._buffer+ebx]
        xor al, al
        rep stosb
        push ebx
        call .display_command
        pop dword [_user_data_command_0._command._length]
    .command_truncate_exit:
        ret

    .command_erase_whole_line:
        call .begin_cursor
        call .command_truncate
        ret
    
    .copy_user_workspace:
        mov ecx, (__user_workspace.sizeof shr 2H)
        rep movsd
        ret

    .clear_user_workspace:
        mov ecx, (__user_workspace.sizeof shr 2H)
        xor eax, eax
        rep stosd
        ret

    .backup_command_to_history:
        mov edi, eax
        mov esi, _user_data_command_0._command
        call .copy_user_workspace
        ret

    .import_command_from_history:
        call .begin_cursor
        mov edi, _user_data_command_0._command
        mov esi, eax
        call .copy_user_workspace
        call .display_command
        call .end_cursor
        ret

    .save_indexed_history:
        mov eax, dword [_user_data_command_0._history_table+eax*4H]
        call .backup_command_to_history
        ret

    .move_up_history:
        cmp byte [_user_data_command_0._history_state], 0H
        jz .move_up_history_exit
        movzx ecx, byte [_user_data_command_0._history_index]
        jecxz .move_up_history_exit
        push ecx
        cmp cl, byte [_user_data_command_0._history_count]
        jnz .move_up_history_refresh
        mov eax, _user_data_command_0._temporary
        call .backup_command_to_history
        jmp $+00AH
    .move_up_history_refresh:
        mov eax, dword [esp]
        call .save_indexed_history
        call .command_erase_whole_line
        pop eax
        mov eax, dword [(_user_data_command_0._history_table-4H)+eax*4H]
        call .import_command_from_history
        dec byte [_user_data_command_0._history_index]
    .move_up_history_exit:
        ret

    .move_down_history:
        cmp byte [_user_data_command_0._history_state], 0H
        jz .move_down_history_exit
        mov cl, byte [_user_data_command_0._history_index]
        mov dl, byte [_user_data_command_0._history_count]
        cmp cl, dl
        jae .move_down_history_exit
        pushw cx dx
        movzx eax, byte [esp+2H]
        call .save_indexed_history
        call .command_erase_whole_line
        popw dx cx
        inc cl
        cmp cl, dl
        jz .move_down_history_temporary
        movzx eax, cl
        mov eax, dword [_user_data_command_0._history_table+eax*4H]
        jmp $+7H
    .move_down_history_temporary:
        mov eax, _user_data_command_0._temporary
        call .import_command_from_history
        inc byte [_user_data_command_0._history_index]
    .move_down_history_exit:
        ret

    .clear_history:
        mov byte [_user_data_command_0._history_count], 0H
        mov byte [_user_data_command_0._history_index], 0H
        ret
    
    .save_history:
        if (_SIZE_HISTORY)
            cmp byte [_user_data_command_0._history_state], 0H
            jz .save_history_exit
            xor ebx, ebx
            movzx eax, byte [_user_data_command_0._history_count]
            cmp eax, _SIZE_HISTORY
            jb .save_history_update
            inc bl
            mov edi, _user_data_command_0._history_table
            mov edx, dword [edi]
            lea esi, [edi+4H]
            mov ecx, (_SIZE_HISTORY - 1H)
            mov eax, ecx
            rep movsd
            mov dword [edi], edx
        .save_history_update:
            call .save_indexed_history
            test ebx, ebx
            jnz .save_history_exit
            inc byte [_user_data_command_0._history_count]
        .save_history_exit:
            mov al, byte [_user_data_command_0._history_count]
            mov byte [_user_data_command_0._history_index], al
        end if
        ret

    .last_line:
        call far _get_cursor_position_gate.selector : 0H
        cmp ebx, (_BOTTOM_SCREEN_ROW - 1H)
        ret

    .index_halve:
        add eax, _user_data._prompt.sizeof
        xor edx, edx
        mov ecx, _VGA_TEXT_COLUMN
        div ecx
        ret

    .return_begin_line:
        call far _get_cursor_position_gate.selector : 0H
        push ebx 0H
        call far _set_cursor_position_gate.selector : 0H
        ret

    .display_command:
        call far _invisible_cursor_gate.selector : 0H
        call .display_command_adjust_halve
        call far _get_cursor_position_gate.selector : 0H
        push ebx eax
        push 0H 0H
        mov eax, dword [_user_data_command_0._cursor]
        call .index_halve
        mov dword [esp+8H], edx
        mov dword [esp], eax
        mov eax, dword [_user_data_command_0._command._length]
        call .index_halve
        mov dword [esp+4H], eax
    .display_command_next:
        call .return_begin_line
        mov eax, dword [esp]
        test eax, eax
        jz .display_command_begin
        dec eax
        mov ebx, _VGA_TEXT_COLUMN
        mul ebx
        lea eax, [_user_data_command_0._command._buffer+(_VGA_TEXT_COLUMN-_user_data._prompt.sizeof)+eax]
        call .display_command_slice
        jmp .display_command_continue
    .display_command_begin:
        push _user_data._prompt.sizeof
        push _user_data._prompt
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        mov eax, _user_data_command_0._command._buffer
        mov ebx, (_VGA_TEXT_COLUMN - _user_data._prompt.sizeof)
        call .display_command_slice
    .display_command_continue:
        inc dword [esp]
        mov eax, dword [esp]
        cmp eax, dword [esp+4H]
        ja .display_command_exit
        call .last_line
        jz .display_command_exit
        call .goto_next_line
        jmp .display_command_next
    .display_command_exit:
        add esp, 8H
        call far _set_cursor_position_gate.selector : 0H
        call far _solid_cursor_gate.selector : 0H
        ret
    .display_command_slice:
        push ebx
        push eax
        sub eax, _user_data_command_0._command._buffer
        mov ecx, dword [_user_data_command_0._command._length]
        sub ecx, eax
        cmp ecx, ebx
        cmovb ebx, ecx
        mov dword [esp+4H], ebx
        push _user_data_command_segment_0.selector
        call far _display_string_gate.selector : 0H
        ret
    .display_command_adjust_halve:
        mov eax, dword [_user_data_command_0._cursor]
        mov ebx, eax
        call .index_halve
        mov ecx, dword [_user_data_command_0._halve]
        mov dword [_user_data_command_0._halve], eax
        sub eax, ecx
        call .scroll_terminal
        ret

    .end_cursor:
        add dword [_user_data_command_0._cursor], _VGA_TEXT_COLUMN
        mov eax, dword [_user_data_command_0._command._length]
        cmp eax, dword [_user_data_command_0._cursor]
        jb @f
        call .display_command
        jmp .end_cursor
    @@:
        mov dword [_user_data_command_0._cursor], eax
        ret

    .cursor_forward:
        mov eax, dword [_user_data_command_0._cursor]
        cmp eax, dword [_user_data_command_0._command._length]
        jae @f
        inc dword [_user_data_command_0._cursor]
    @@:
        ret

    .begin_cursor:
        mov dword [_user_data_command_0._cursor], 0H
        ret

    .cursor_backward:
        mov eax, dword [_user_data_command_0._cursor]
        test eax, eax
        jz @f
        dec dword [_user_data_command_0._cursor]
    @@:
        ret

    _PLUS_LINE_ENTER = 2H
    .retablish_shell:
        cmp byte [fs:_user_data._cleared], 1H
        jz .retablish_shell_clear
        mov eax, _PLUS_LINE_ENTER
        call .scroll_terminal
        jmp .retablish_shell_exit
    .retablish_shell_clear:
        call .clear_history
        mov byte [fs:_user_data._cleared], 0H
    .retablish_shell_exit:
        mov edi, _user_data_command_0._temporary
        call .clear_user_workspace
        mov edi, _user_data_command_0._command
        call .clear_user_workspace
        mov dword [_user_data_command_0._cursor], eax
        mov dword [_user_data_command_0._command._length], eax
        mov dword [_user_data_command_0._halve], eax
        call .display_command
        ret

    .display_bottom:
        call far _retreive_screen_gate.selector : 0H
        mov ecx, eax
        mov edi, _user_data._bottom + 1H
        jecxz .display_bottom_next
        add edi, 3H
        loop ($ - 3H)
    .display_bottom_next:
        push edi
        mov byte [fs:edi], 02AH
        call far _get_cursor_position_gate.selector : 0H
        push ebx eax
        push _BOTTOM_SCREEN_ROW
        push 0H
        call far _set_cursor_position_gate.selector : 0H
        push _user_data._bottom.sizeof
        push _user_data._bottom
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        call far _set_cursor_position_gate.selector : 0H
        pop edi
        mov byte [fs:edi], 020H
        ret

    .scroll_terminal:
        test eax, eax
        jnz @f
        ret
    @@:
        push eax
        call far _get_cursor_position_gate.selector : 0H
        pop eax
        xor edx, edx
        add ebx, eax
        jns @f
        neg ebx
        mov eax, ebx
        mov ebx, _SCROLL_DOWN
        call .scroll_terminal_invoke
        xor ebx, ebx
        inc dl
    @@:
        push ebx 0H
        test dl, dl
        jnz .scroll_terminal_update
        lea eax, [ebx+1H]
        sub eax, _BOTTOM_SCREEN_ROW
        jbe .scroll_terminal_update
        mov ebx, _SCROLL_UP
        call .scroll_terminal_invoke
        mov dword [esp+4H], (_BOTTOM_SCREEN_ROW - 1H)
    .scroll_terminal_update:
        call far _set_cursor_position_gate.selector : 0H
        ret
    .scroll_terminal_invoke:
        push (_VGA_TEXT_COLUMN - 1H)
        push (_BOTTOM_SCREEN_ROW - 1H)
        push 0H 0H 0H
        push eax
        push ebx
        call far _scroll_gate.selector : 0H
        ret

    .goto_next_line:
        mov eax, 1H
        call .scroll_terminal
        ret

    .word_compare:
        push edi ecx
        xor edx, edx
        sub ecx, eax
        jb .word_compare_carry
        setz dl
        xchg eax, ecx
        fs repz cmpsb
        jnz .word_compare_carry
        test dl, dl
        jnz .word_compare_match
        cmp byte [edi], 020H
        jnz .word_compare_carry
    .word_compare_match:
        add esp, 8H
        clc
        mov ecx, eax
        jmp $+5H
    .word_compare_carry:
        pop ecx edi
        stc
        ret

    .parse_command:
      ; parse command
      ;  in:
      ;   eax - size of the tested string
      ;   ebx - predicate to call if the string match
      ;   ecx - size of the command buffer entered by the user
      ;   edi - command buffer
      ;   esi - tested string
        call .word_compare
        jc .parse_command_exit
        call ebx
        clc
    .parse_command_exit:
        ret
    
    .ensure_no_params:
        call .skip_whitespace
        jz .ensure_no_params_exit
        push _user_data._bad_params.sizeof
        push _user_data._bad_params
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        stc
        jmp $+3H
    .ensure_no_params_exit:
        clc
        ret

    .skip_whitespace:
        ;jecxz .skip_whitespace_empty
        test ecx, ecx ; Z flag
        jz .skip_whitespace_empty
        mov al, 020H
        repz scasb
        jz .skip_whitespace_empty
        lea edi, [edi-1H]
        lea ecx, [ecx+1H]
    .skip_whitespace_empty:
        ret

    .command_unknown:
        push _user_data._unknown.sizeof
        push _user_data._unknown
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        ret

    define _HELP_COUNT 011H
    .command_help:
        call .ensure_no_params
        jc .command_help_exit
        rept _HELP_COUNT i:1H
        {
            push _user_data._help_#i#.sizeof
            push _user_data._help_#i
            push _user_data_segment.selector
            call far _display_string_gate.selector : 0H
            if ((i) <> _HELP_COUNT)
                call .goto_next_line
            end if
        }
    .command_help_exit:
        ret

    define _COPYRIGHT_COUNT 2H
    .command_copyright:
        call .ensure_no_params
        jc .command_copyright_exit
        rept _COPYRIGHT_COUNT i:1H
        {
            push _user_data._copyright_#i#.sizeof
            push _user_data._copyright_#i
            push _user_data_segment.selector
            call far _display_string_gate.selector : 0H
            if ((i) <> _COPYRIGHT_COUNT)
                call .goto_next_line
            end if
        }
    .command_copyright_exit:
        ret

    .command_clear:
        call .ensure_no_params
        jc .command_clear_exit
        push _VGA_BLACK
        call far _set_background_gate.selector : 0H
        push _VGA_LIGHT
        call far _set_foreground_gate.selector : 0H
        mov eax, _BOTTOM_SCREEN_ROW
        call .scroll_terminal
        push 0H 0H
        call far _set_cursor_position_gate.selector : 0H
        mov byte [fs:_user_data._cleared], 1H
    .command_clear_exit:
        ret

    .switch_next:
        call far _retreive_screen_gate.selector : 0H
        inc eax
        xor ecx, ecx
        cmp eax, _SCREEN_COUNT
        cmovz eax, ecx
        push eax
        call far _switch_screen_gate.selector : 0H
        ret

    .switch_back:
        call far _retreive_screen_gate.selector : 0H
        mov ecx, _SCREEN_COUNT
        test eax, eax
        cmovz eax, ecx
        dec eax
        push eax
        call far _switch_screen_gate.selector : 0H
        ret

    .command_switch:
        call .skip_whitespace
        jz .command_switch_invalid
        push ecx
        push edi
        push _user_data_command_segment_0.selector
        call far _atoi_gate.selector : 0H
        jc .command_switch_invalid
        mov ebx, eax
        call .ensure_no_params
        jc .command_switch_exit
        push ebx
        call far _switch_screen_gate.selector : 0H
        jnc .command_switch_exit
    .command_switch_invalid:
        push _user_data._switch_1.sizeof
        push _user_data._switch_1
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
    .command_switch_exit:
        ret

    .command_cmatrix:
        call .ensure_no_params
        jc .command_cmatrix_exit
        int 042H
        call far _refresh_screen_gate.selector : 0H
    .command_cmatrix_exit:
        ret

    irp kind*, fg,bg
    {
        .command_#kind:
            call .skip_whitespace
            jz .command_#kind#_invalid
            rept 8H i:1H
            \{
                mov esi, _user_data._color_\#i
                mov eax, _user_data._color_\#i\#.sizeof
                call .word_compare
                mov ebx, _user_data._color_value_\#i
                jnc .command_#kind#_match
            \}
            jmp .command_#kind#_invalid
        .command_#kind#_match:
            call .ensure_no_params
            jc .command_#kind#_exit
            push ebx
            match =fg, kind \{ call far _set_foreground_gate.selector : 0H \}
            match =bg, kind \{ call far _set_background_gate.selector : 0H \}
            jmp .command_#kind#_exit
        .command_#kind#_invalid:
            push _user_data._fg_bg_1.sizeof
            push _user_data._fg_bg_1
            push _user_data_segment.selector
            call far _display_string_gate.selector : 0H
        .command_#kind#_exit:
            ret
    }

    .command_unreal:
        call .ensure_no_params
        jc .command_unreal_exit
        call far _unreal_realm_gate.selector : 0H
    .command_unreal_exit:
        ret

    .parse_string:
        push edi ecx
        cmp ecx, 2H
        jb .parse_string_carry
        mov esi, edi
        dec ecx
        lodsb
        call .parse_string_delim
        jnz .parse_string_carry
        mov dl, al
        mov edi, _user_data_command_0._temporary._buffer
        mov ebx, ecx
    @@:
        lodsb
        cmp al, dl
        jnz .parse_string_store
        dec ecx     
        jecxz .parse_string_save
        lodsb
        cmp al, dl
        jnz .parse_string_adjust_pointer
        dec ebx
    .parse_string_store:
        stosb
        loop @b
        jmp .parse_string_carry
    .parse_string_adjust_pointer:
        dec esi
    .parse_string_save:
        sub ebx, ecx
        dec ebx
        mov dword [_user_data_command_0._temporary._length], ebx
        mov edi, esi
        add esp, 8H
        clc
        jmp $+5H
    .parse_string_carry:
        pop ecx edi
        stc
        ret
    .parse_string_delim:
        cmp al, 022H
        jz @f
        cmp al, 027H
    @@:
        ret
    
    .command_copy:
        call .skip_whitespace
        jz .command_copy_invalid
        call .parse_string
        jc @f
    .command_copy_sanitize:
        call .ensure_no_params
        jc .command_copy_exit
        mov edi, _user_data_command_0._copy
        mov esi, _user_data_command_0._temporary
        call .copy_user_workspace
        jmp .command_copy_exit
    @@:
        mov esi, edi
        mov al, 020H
        repnz scasb
        jnz @f
        dec edi
        inc ecx
    @@:
        push edi ecx
        mov ecx, edi
        sub ecx, esi
        mov dword [_user_data_command_0._temporary._length], ecx
        mov edi, _user_data_command_0._temporary._buffer
        rep movsb
        pop ecx edi
        jmp .command_copy_sanitize
    .command_copy_invalid:
        push _user_data._copy_1.sizeof
        push _user_data._copy_1
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
    .command_copy_exit:
        ret

    .command_history:
        call .skip_whitespace
        jz .command_history_invalid
        rept 2H i:2H
        {
            mov esi, _user_data._history_#i
            mov eax, _user_data._history_#i#.sizeof
            call .word_compare
            mov bl, _user_data._history_value_#i
            jnc .command_history_match
        }
        jmp .command_history_invalid
    .command_history_match:
        call .ensure_no_params
        jc .command_history_exit
        mov byte [_user_data_command_0._history_state], bl
        test bl, bl
        jnz .command_history_exit
        call .clear_history
        jmp .command_history_exit
    .command_history_invalid:
        push _user_data._history_1.sizeof
        push _user_data._history_1
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
    .command_history_exit:
        ret

    .character_printable:
        cmp al, 020H
        jc $+5H
        cmp al, 07FH
        cmc
        ret

    .carried_number:
      ; Return the number +1H to produce a carry.
      ; Why +1H? Because when you have zero you can't carry.
      ; This is why I need 0FFFFFFFFH + 1H to be representable in a dword.
        xor ecx, ecx
        sub ecx, eax
        jnz @f
        not ecx
        jmp $+3H
    @@: 
        dec ecx
        mov eax, ecx
        ret

    .print_character:
        mov byte [fs:_user_data._character], al
        push 1H
        push _user_data._character
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        ret
    
    .padding_space:
        cmp eax, _VGA_TEXT_COLUMN
        jae .padding_space_exit
        push eax
        call far _get_cursor_position_gate.selector : 0H
        pop ecx
        sub ecx, eax
        jbe .padding_space_exit
    @@:
        push ecx
        mov al, 020H
        call .print_character
        pop ecx
        loop @b
    .padding_space_exit:
        ret

    .display_integer:
        push ebx
        push ebx
        push _user_data._result_itoa
        push _user_data_segment.selector
        push eax
        call far _itoa_gate.selector : 0H
        push eax
        push _user_data._result_itoa
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        ret

    _COUNT_BYTE_ROW = 010H
    assert (((bsf _COUNT_BYTE_ROW) = (bsr _COUNT_BYTE_ROW)) & (_COUNT_BYTE_ROW))
    .command_dump:
        push ebp
        mov ebp, esp
        call .skip_whitespace
        jz .command_dump_invalid
        push ecx
        push edi
        push _user_data_command_segment_0.selector
        call far _atoi_gate.selector : 0H
        jc .command_dump_invalid
        push 1H 1H eax 0H
        call .skip_whitespace
        jz @f
        dec ecx
        mov al, 02CH
        scasb
        jnz .command_dump_invalid
        call .skip_whitespace
        jz .command_dump_invalid
        push ecx
        push edi
        push _user_data_command_segment_0.selector
        call far _atoi_gate.selector : 0H
        jc .command_dump_invalid
        mov dword [esp+8H], eax
        call .ensure_no_params
        jc .command_dump_exit
    @@:
        mov eax, dword [esp+8H]
        test eax, eax
        jz .command_dump_exit
        mov ecx, (bsf _COUNT_BYTE_ROW)
    @@:
        shl eax, 1H
        jc @f
        loop @b  
        dec eax
        jmp .command_dump_limit
    @@:
        xor eax, eax
        not eax    
    .command_dump_limit:
        mov ebx, eax
        mov eax, dword [esp+4H]
        call .carried_number
        cmp eax, ebx
        cmova eax, ebx
        mov dword [esp+8H], eax
        mov ax, _flat_memory_segment.selector
        mov ds, ax
    .command_dump_row:
        mov eax, dword [esp+4H]
        mov ebx, _PADDING_MAX
        call .display_integer
        push _user_data._dump_3.sizeof
        push _user_data._dump_3
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
    @@:
        mov ebx, dword [esp+4H]
        mov eax, dword [esp]
        movzx ebx, byte [ebx+eax]
        mov eax, ebx
        xor dl, dl
    .command_dump_convert:
        call .character_printable 
        jnc .command_dump_dot
        mov al, 02EH
    .command_dump_dot:
        or dl, al
        mov eax, dword [esp]
        mov byte [fs:_user_data._dump_4+1H+eax], dl
        mov eax, 2H
        xchg ebx, eax
        call .display_integer
        mov al, 020H
        call .print_character
        inc dword [esp]
        mov eax, dword [esp+8H]
        sub eax, 1H
        mov dword [esp+8H], eax
        jc @f
        cmp dword [esp], _COUNT_BYTE_ROW
        jb @b
        jmp $+00AH
    @@:
        mov dword [esp+00CH], 0H
        mov eax, _user_data._dump_padding
        call .padding_space
        mov eax, dword [esp]
        mov byte [fs:_user_data._dump_4+1H+eax], 07CH
        lea edx, [eax+2H]
        push edx
        push _user_data._dump_4
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        mov dword [esp], 0H
        call .goto_next_line
        add dword [esp+4H], _COUNT_BYTE_ROW
        cmp dword [esp+00CH], 0H
        jnz .command_dump_row
        jmp .command_dump_exit
    .command_dump_invalid:
        push _user_data._dump_1.sizeof
        push _user_data._dump_1
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
    .command_dump_exit:
        pushw es
        popw ds
        leave
        ret

    .command_find:
        push ebp
        mov ebp, esp
        call .skip_whitespace
        jz .command_find_invalid
        mov esi, edi
        dec ecx
        lodsb
        call .command_find_attribute
        jnz .command_find_invalid
        inc edi
        call .skip_whitespace
        jz .command_find_invalid
        push ebx
        call .parse_string
        jc @f
        mov eax, dword [_user_data_command_0._temporary._length]
        cmp eax, dword [esp]
        ja .command_find_invalid
        test eax, eax
        jz .command_find_invalid
        mov eax, dword [_user_data_command_0._temporary._buffer]
        jmp .command_find_sanitize
    @@:
        push ecx
        push edi
        push _user_data_command_segment_0.selector
        call far _atoi_gate.selector : 0H
        jc .command_find_invalid
    .command_find_sanitize:
        mov ebx, dword [esp]
        cmp bl, 4H 
        jz .command_find_base_address
        cmp bl, 2H
        jnz @f
        cmp eax, 0FFFFH
        ja .command_find_invalid
        jmp .command_find_base_address
    @@:
        cmp eax, 0FFH
        ja .command_find_invalid
    .command_find_base_address:
        push eax
        call .skip_whitespace
        jz .command_find_invalid
        push ecx
        push edi
        push _user_data_command_segment_0.selector
        call far _atoi_gate.selector : 0H
        jc .command_find_invalid
        push eax
        call .skip_whitespace
        jz .command_find_invalid
        dec ecx
        mov al, 02CH
        scasb
        jnz .command_find_invalid
        call .skip_whitespace
        jz .command_find_invalid
        push ecx
        push edi
        push _user_data_command_segment_0.selector
        call far _atoi_gate.selector : 0H
        jc .command_find_invalid
        mov ebx, eax
        call .ensure_no_params
        jc .command_find_exit
        test ebx, ebx
        jz .command_find_not_enough_space
        dec ebx ; dec don't affect the carry flag ;(
        mov eax, dword [esp]
        call .carried_number
        cmp eax, ebx
        cmova eax, ebx
        mov ebx, dword [esp+8H]
        dec ebx
        cmp eax, ebx
        jb .command_find_not_enough_space
        not ebx
        and eax, ebx
        mov ecx, eax
        shr dword [esp+8H], 1H 
        mov ax, _flat_memory_segment.selector
        mov es, ax
    @@:
        mov edi, dword [esp]
        mov eax, dword [esp+4H]
        mov ebx, dword [esp+8H]
        call dword [cs:.command_find_table+ebx*4H]
        jnz .command_find_next
        push ecx
        push _user_data._find_3.sizeof
        push _user_data._find_3
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        mov eax, dword [esp+4H]
        mov ebx, _PADDING_MAX
        call .display_integer
        call .goto_next_line
        pop ecx
    .command_find_next:
        inc dword [esp]
        jecxz .command_find_exit
        dec ecx
        jmp @b
    .command_find_invalid:
        push _user_data._find_1.sizeof
        push _user_data._find_1
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
    .command_find_exit:
        pushw ds
        popw es
        leave
        ret
    .command_find_not_enough_space:
        push _user_data._find_2.sizeof
        push _user_data._find_2
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        jmp .command_find_exit
    .command_find_attribute:    
        xor ebx, ebx
        cmp al, 062H
        mov bl, 1H
        jz @f
        cmp al, 077H
        mov bl, 2H
        jz @f
        cmp al, 064H
        mov bl, 4H
    @@:
        ret
    .command_find_byte:
        scasb
        ret
    .command_find_word:
        scasw
        ret
    .command_find_dword:
        scasd
        ret
    .command_find_table:
        dd .command_find_byte
        dd .command_find_word
        dd .command_find_dword

    .command_register:
        pushf
        pushad
        call .ensure_no_params
        jc .command_register_exit
    rept 8H i:1H
    {
        mov eax, _user_data._register_#i#.sizeof
        mov ebx, _user_data._register_#i
        rept 1H j:(8H-i) \{ mov ecx, dword [esp+(j*4H)] \}
        call .command_register_display_32_register_with_scroll
    }
        mov eax, _user_data._register_9.sizeof
        mov ebx, _user_data._register_9
        mov ecx, .command_register
        call .command_register_display_32_register_with_scroll
        mov eax, _user_data._register_10.sizeof
        mov ebx, _user_data._register_10
        mov ecx, dword [esp+020H]
        call .command_register_display_32_register
        mov al, 020H
        call .print_character
        mov al, 05BH
        call .print_character
        mov al, 020H
        call .print_character
    irp tested*, 0,2,4,6,7,8,9,10,11,12,14,16,17,18,19,20,21
    {
    reverse
        mov eax, dword [esp+020H]
        if ((tested) = 00CH)
            shr eax, 00CH
            and eax, 011B
            push eax
        else
            test eax, (1H shl tested)
            jz @f
        end if
        push _user_data._register_10_#tested#.sizeof
        push _user_data._register_10_#tested
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        if ((tested) = 00CH)
            mov al, 03DH
            call .print_character
            pop eax
            mov ebx, 1H
            call .display_integer
        end if
        mov al, 020H
        call .print_character
    @@:
    }
        mov al, 05DH
        call .print_character
        call .goto_next_line
        sgdt fword [esp]
        mov eax, _user_data._register_11.sizeof
        mov ebx, _user_data._register_11
        call .command_register_display_descriptor_register
        sidt fword [esp]
        mov eax, _user_data._register_12.sizeof
        mov ebx, _user_data._register_12
        call .command_register_display_descriptor_register
        sldt ax
        str bx
        pushw gs fs es ss ds cs bx ax
    rept 8H i:00DH
    {
        mov eax, _user_data._register_#i#.sizeof
        mov ebx, _user_data._register_#i
        movzx ecx, word [esp+((i-00DH)*2H)]
        call .command_register_display_16_register
    }
        add esp, 010H
    .command_register_exit:
        add esp, 024H
        ret
    .command_register_display_32_register:
        mov edx, 8H
        call .command_register_display_register
        ret
    .command_register_display_32_register_with_scroll:
        mov edx, 8H
        call .command_register_display_register
        call .goto_next_line
        ret
    .command_register_display_16_register:
        mov edx, 4H
        call .command_register_display_register
        call .goto_next_line
        ret
    .command_register_display_descriptor_register:
        call .command_register_display_info
        movzx eax, word [esp+4H]
        mov ebx, 4H
        call .display_integer
        mov al, 03AH
        call .print_character
        mov eax, dword [esp+6H]
        mov ebx, 8H
        call .display_integer
        call .goto_next_line
        ret
    .command_register_display_register:
        push edx ecx
        call .command_register_display_info
        pop eax ebx
        call .display_integer
        ret
    .command_register_display_info:
        push eax
        push ebx
        push _user_data_segment.selector
        call far _display_string_gate.selector : 0H
        mov eax, _user_data._register_padding
        call .padding_space
        ret
    
    .command_reboot:
        call .ensure_no_params
        jc .command_reboot_exit
        push 0DEADC0DEH
        call far _reboot_gate.selector : 0H
    .command_reboot_exit:
        ret

    .command_shutdown:
        call .ensure_no_params
        jc .command_shutdown_exit
        push 0DEEDFADEH
        call far _shutdown_gate.selector : 0H
    .command_shutdown_exit:
        ret
end psegment

psegment _user_data
    ._help string "help"
    ._help_1  string "achiu-au, KFS version 1.0.2"
    ._help_2  string "help               - display help"
    ._help_3  string "copyright          - show the copyright"
    ._help_4  string "unreal             - goto the unreal realm"
    ._help_5  string "cmatrix            - launch cmatrix ;)"
    ._help_6  string "switch n           - switch to the nth screen"
    ._help_7  string "clear              - clear the current screen and the history"
    ._help_8  string "fg/bg c            - change foreground/background to c"
    ._help_9  string " * [black,blue,green,cyan,red,magenta,brown,light]"
    ._help_10 string "copy ""str""         - copy the string to the clipboard"
    ._help_11 string " * to include "" in string, double it"
    ._help_12 string "history on/off     - enable/disable history"
    ._help_13 string "dump n [,c]        - dump memory at address n up to n+c"
    ._help_14 string "find [b,w,d] p n,c - find the pattern in memory n up to n+c"
    ._help_15 string "register           - show register"
    ._help_16 string "reboot             - reboot the machine"
    ._help_17 string "shutdown           - shutdown the machine"
    ._copyright string "copyright"
    ._copyright_1 string "copyright @ achiu-au"
    ._copyright_2 string "License MIT, this kernel is for educational purpose only"
    ._clear string "clear"
    ._cleared: db 0H
    ._switch string "switch"
    ._switch_1 string "switch invalid"
    ._cmatrix string "cmatrix"
    ._fg string "fg"
    ._bg string "bg"
    ._fg_bg_1 string "invalid color"
    ._color_1 string "black"
    ._color_2 string "blue"
    ._color_3 string "green"
    ._color_4 string "cyan"
    ._color_5 string "red"
    ._color_6 string "magenta"
    ._color_7 string "brown"
    ._color_8 string "light"
    ._color_value_1 = _VGA_BLACK
    ._color_value_2 = _VGA_BLUE
    ._color_value_3 = _VGA_GREEN
    ._color_value_4 = _VGA_CYAN
    ._color_value_5 = _VGA_RED
    ._color_value_6 = _VGA_MAGENTA
    ._color_value_7 = _VGA_BROWN
    ._color_value_8 = _VGA_LIGHT
    ._unreal string "unreal"
    ._copy string "copy"
    ._copy_1 string "copy invalid"
    ._history string "history"
    ._history_1 string "history invalid"
    ._history_2 string "on"
    ._history_3 string "off"
    ._history_value_2 = 1H
    ._history_value_3 = 0H
    ._dump string "dump"
    ._dump_1 string "dump invalid"
    ._dump_3 string ": "
    ._dump_4 string "|................|"
    ._dump_padding = (_PADDING_MAX + ._dump_3.sizeof + ((2H + 1H) * _COUNT_BYTE_ROW))
    ._find string "find"
    ._find_1 string "find invalid"
    ._find_2 string "no enough space"
    ._find_3 string "found pattern at: "
    ._register string "register"
    ._register_padding = 8H
    ._register_1  string "eax"
    ._register_2  string "ecx"
    ._register_3  string "edx"
    ._register_4  string "ebx"
    ._register_5  string "esp"
    ._register_6  string "ebp"
    ._register_7  string "esi"
    ._register_8  string "edi"
    ._register_9  string "eip"
    ._register_10 string "eflags"
    ._register_10_0  string "CF"
    ._register_10_2  string "PF"
    ._register_10_4  string "AF"
    ._register_10_6  string "ZF"
    ._register_10_7  string "SF"
    ._register_10_8  string "TF"
    ._register_10_9  string "IF"
    ._register_10_10 string "DF"
    ._register_10_11 string "OF"
    ._register_10_12 string "IOPL"
    ._register_10_14 string "NT"
    ._register_10_16 string "RF"
    ._register_10_17 string "VM"
    ._register_10_18 string "AC"
    ._register_10_19 string "VIF"
    ._register_10_20 string "VIP"
    ._register_10_21 string "ID"
    ._register_11 string "gdtr"
    ._register_12 string "idtr"
    ._register_13 string "ldtr"
    ._register_14 string "tr"
    ._register_15 string "cs"
    ._register_16 string "ds"
    ._register_17 string "ss"
    ._register_18 string "es"
    ._register_19 string "fs"
    ._register_20 string "gs"
    ._reboot string "reboot"
    ._shutdown string "shutdown"
    ._unknown string "unknown command"
    ._bad_params string "bad parameter"
    ._prompt string "achiu-au@42> "
    ._character: db 0H
    ._result_itoa: db _PADDING_MAX dup 0H
    ._bottom:
    rept _SCREEN_COUNT { db "[ ]" }
    ._bottom.sizeof = ($ - ._bottom)
    rept _SCREEN_COUNT i:0H
    {
        psegment _user_data_command_#i
            ._command __user_workspace
            ._cursor: dd 0H
            ._halve: dd 0H
            ._last: db 0H
            ._copy __user_workspace
            ._history_state: db 1H
            ._history_index: db 0H
            ._history_count: db 0H
            ._history_table:
            rept _SIZE_HISTORY j:0H \{ dd ._history_\#j \}
            rept _SIZE_HISTORY j:0H \{ ._history_\#j __user_workspace \}
            ._temporary __user_workspace
        end psegment
    }
end psegment

rept _SCREEN_COUNT i:0H { __declare_stack _user_stack_#i }

reserve _flat_unreal_code, 0H, 10000H
reserve _flat_unreal_data, 0H, 10000H
reserve _video_memory_text_vga, (_VGA_MEMORY_SEG shl 4H), _VGA_MEMORY_SIZE

define _GDT_EMPTY_SLOT 020H
define _LDT_EMPTY_SLOT 010H

_start_memory = 0H
_segsize _whole_memory, 0100000H

_GDT_BASE_ADDRESS = 800H
descriptor_table _GDT
    _null_segment DT_null
    _kernel_elf_segment DT_dte _D, _PRESENT or _DPL0 or _EXECUTABLE or _READABLE, _kernel_elf_entry, _kernel_elf_entry.size
    _unreal_code_segment DT_dte 0H, _PRESENT or _DPL0 or _EXECUTABLE or _READABLE, _flat_unreal_code, _flat_unreal_code.size
    _unreal_data_segment DT_dte 0H, _PRESENT or _DPL0 or _WRITABLE, _flat_unreal_data, _flat_unreal_data.size
    _flat_memory_segment DT_dte _G, _PRESENT or _DPL3, _start_memory, _whole_memory
    _video_segment DT_dte 0H, _PRESENT or _DPL0 or _WRITABLE, _video_memory_text_vga, _video_memory_text_vga.size
    _kernel_code_segment DT_dte _D, _PRESENT or _DPL0 or _EXECUTABLE or _READABLE, _kernel_code, _kernel_code.size
    _kernel_data_segment DT_dte 0H, _PRESENT or _DPL0 or _WRITABLE, _kernel_data, _kernel_data.size
    _user_code_segment DT_dte _D, _PRESENT or _DPL3 or _EXECUTABLE or _READABLE, _user_code, _user_code.size
    _user_data_segment DT_dte 0H, _PRESENT or _DPL3 or _WRITABLE, _user_data, _user_data.size
    _display_string_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 3H, _kernel_code_segment.selector, _kernel_code.display_string
    _atoi_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 3H, _kernel_code_segment.selector, _kernel_code.atoi
    _itoa_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 5H, _kernel_code_segment.selector, _kernel_code.itoa
    _switch_screen_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 1H, _kernel_code_segment.selector, _kernel_code.switch_screen 
    _retreive_screen_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 0H, _kernel_code_segment.selector, _kernel_code.retreive_screen
    _set_cursor_position_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 2H, _kernel_code_segment.selector, _kernel_code.set_cursor_position
    _get_cursor_position_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 0H, _kernel_code_segment.selector, _kernel_code.get_cursor_position
    _invisible_cursor_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 0H, _kernel_code_segment.selector, _kernel_code.invisible_cursor
    _solid_cursor_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 0H, _kernel_code_segment.selector, _kernel_code.solid_cursor
    _scroll_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 7H, _kernel_code_segment.selector, _kernel_code.scroll
    _read_keyboard_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 3H, _kernel_code_segment.selector, _kernel_code.read_keyboard
    _refresh_screen_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 0H, _kernel_code_segment.selector, _kernel_code.refresh_screen
    _reboot_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 1H, _kernel_code_segment.selector, _kernel_code.reboot
    _shutdown_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 1H, _kernel_code_segment.selector, _kernel_code.shutdown
    _set_foreground_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 1H, _kernel_code_segment.selector, _kernel_code.set_foreground
    _set_background_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 1H, _kernel_code_segment.selector, _kernel_code.set_background
    _unreal_realm_gate DT_gte _PRESENT or _DPL3 or _386_CALL_GATE, 0H, _kernel_code_segment.selector, _kernel_code.unreal_realm
    rept _SCREEN_COUNT i:0H
    {
        _tss_screen_segment_#i DT_ste _PRESENT or _DPL0 or _386_TSS, _kernel_screen_#i#_tss, _kernel_screen_#i#_tss.size
        _ldt_screen_segment_#i DT_ste _PRESENT or _DPL0 or _286_LDT, _LDT_#i, _LDT_#i#.size
    }
    _tss_cmatrix DT_ste _PRESENT or _DPL0 or _386_TSS, _cmatrix_screen_tss, _cmatrix_screen_tss.size
    _ldt_cmatrix DT_ste _PRESENT or _DPL0 or _286_LDT, _LDT_cmatrix, _LDT_cmatrix.size
    rept _GDT_EMPTY_SLOT { DT_null }
end descriptor_table

descriptor_table _IDT
    define _IDT_IRQ_COUNT (_INTEL_RESERVED_INT + (_IBM_PIC_HANDLE_INT * 2H))
    rept _IDT_IRQ_COUNT i:0H
        { DT_gte _PRESENT or _DPL0 or _386_INTERRUPT_GATE, 0H, _kernel_code_segment.selector, _kernel_code._handler_#i }
    rept (042H - _IDT_IRQ_COUNT) { DT_null }
    DT_gte _PRESENT or _DPL3 or _286_TASK_GATE, 0H, _tss_cmatrix.selector, 0H
end descriptor_table

_unreal_idt = 0H
_segsize _unreal_idt.size, 100H * 4H

rept _SCREEN_COUNT i:0H
{
    descriptor_table _LDT_#i, 1H
        _screen_segment_kernel_#i DT_dte 0H, _PRESENT or _DPL0 or _WRITABLE, _kernel_screen_#i, _kernel_screen_#i#.size
        _kernel_stack_segment_#i DT_dte _B, _PRESENT or _DPL0 or _WRITABLE, _kernel_stack_#i, _kernel_stack_#i#.size
        _user_data_command_segment_#i DT_dte 0H, _PRESENT or _DPL3 or _WRITABLE, _user_data_command_#i, _user_data_command_#i#.size
        _user_stack_segment_#i DT_dte _B, _PRESENT or _DPL3 or _WRITABLE, _user_stack_#i, _user_stack_#i#.size
        rept _LDT_EMPTY_SLOT \{ DT_null \}
    end descriptor_table
}

descriptor_table _LDT_cmatrix, 1H
    _cmatrix_screen_segment DT_dte 0H, _PRESENT or _DPL0 or _WRITABLE, _cmatrix_screen, _cmatrix_screen.size
    _cmatrix_misc_segment DT_dte 0H, _PRESENT or _DPL0 or _WRITABLE, _cmatrix_misc, _cmatrix_misc.size
    _cmatrix_stack_segment DT_dte _B, _PRESENT or _DPL0 or _WRITABLE, _cmatrix_stack, _cmatrix_stack.size
end descriptor_table
