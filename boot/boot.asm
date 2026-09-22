; ============================================================
;  boot.asm  —  FENIX OS Stage-1 Bootloader
;  Projekt: AnonNet / Fenix  |  Faza 3 (Fenix OS ISO)
;  Kompilacja: nasm -f bin boot.asm -o boot.bin
; ------------------------------------------------------------
;  Zadania:
;   1) BIOS wrzuca ten kod pod adres 0x7C00
;   2) Wczytujemy kernel (LBA 1)      -> pamiec 0x10000
;   3) Wczytujemy ZASZYFROWANY magazyn
;      kluczy zbiorczych (LBA 49)     -> pamiec 0x20000
;   4) Włączamy linię A20 i tryb chroniony (32-bit)
;   5) Skaczemy do kernela, podając mu adres magazynu w EBX
; ============================================================

[BITS 16]
[ORG 0x7C00]

%define KERNEL_SEG        0x1000      ; kernel wyladuje pod fizycznym 0x10000
%define KERNEL_LBA        1           ; kernel zaczyna sie od sektora 1 (zaraz po boot)
%define KERNEL_SECTORS    48          ; 48 * 512 = 24 KB miejsca na kernel

%define KEYSTORE_SEG      0x2000      ; keystore wyladuje pod fizycznym 0x20000
%define KEYSTORE_LBA      49          ; magazyn kluczy zaraz za kernelem
%define KEYSTORE_SECTORS  8           ; 8 * 512 = 4 KB na zaszyfrowane klucze

start:
    cli                             ; wylacz przerwania na czas ustawiania stosu
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00                  ; stos pod bootloaderem
    sti

    mov [BOOT_DRIVE], dl            ; BIOS podaje nr dysku w DL — zapisz go!

    mov si, MSG_BOOT
    call print16

; ------------------------------------------------------------
; WCZYTAJ KERNEL  (BIOS int 13h, AH=42h — odczyt LBA/EDD)
; ------------------------------------------------------------
    mov word [DAP + 2], KERNEL_SECTORS
    mov word [DAP + 4], 0x0000          ; offset bufora
    mov word [DAP + 6], KERNEL_SEG      ; segment bufora
    mov dword [DAP + 8], KERNEL_LBA     ; LBA (mlodsze 32 bity)
    mov dword [DAP + 12], 0             ; LBA (starsze 32 bity)
    call read_disk
    jc disk_error

; ------------------------------------------------------------
; WCZYTAJ ZASZYFROWANY MAGAZYN KLUCZY ZBIORCZYCH
; (w pamieci jest NADAL zaszyfrowany — kernel go otworzy)
; ------------------------------------------------------------
    mov word [DAP + 2], KEYSTORE_SECTORS
    mov word [DAP + 4], 0x0000
    mov word [DAP + 6], KEYSTORE_SEG
    mov dword [DAP + 8], KEYSTORE_LBA
    mov dword [DAP + 12], 0
    call read_disk
    jc disk_error

    mov si, MSG_LOAD_OK
    call print16

; ------------------------------------------------------------
; WLACZ LINIE A20 (dostep do pamieci powyzej 1 MB)
; ------------------------------------------------------------
    in al, 0x92
    or al, 0x02
    and al, 0xFE                      ; bit0 musi zostac 0 (to reset!)
    out 0x92, al

; ------------------------------------------------------------
; ZALADUJ GDT I PRZEJDZ W TRYB CHRONIONY (32-bit)
; ------------------------------------------------------------
    lgdt [gdt_desc]

    mov eax, cr0
    or eax, 1                         ; bit PE = protected mode ON
    mov cr0, eax

    jmp 0x08:pm_entry               ; daleki skok = odswiezenie cache CPU

; ============================================================
;  FUNKCJE 16-BITOWE
; ============================================================
print16:                            ; wypisz string z SI (zakonczony bajtem 0)
    lodsb
    or al, al
    jz .done
    mov ah, 0x0E                    ; BIOS teletype
    int 0x10
    jmp print16
.done:
    ret

read_disk:                          ; czyta wg pakietu DAP; CF=1 gdy blad
    mov si, DAP
    mov ah, 0x42                    ; EDD: Extended Read
    mov dl, [BOOT_DRIVE]
    int 0x13
    ret

disk_error:
    mov si, MSG_DISK_ERR
    call print16
.hang:                              ; bezpieczne zatrzymanie — NIC nie zapisujemy
    cli
    hlt
    jmp .hang

; ============================================================
;  DANE
; ============================================================
BOOT_DRIVE   db 0
MSG_BOOT     db "FENIX OS :: boot start...", 13, 10, 0
MSG_LOAD_OK  db "FENIX OS :: kernel + keystore OK", 13, 10, 0
MSG_DISK_ERR db "FENIX OS :: BLAD DYSKU — STOP.", 13, 10, 0

; -- Disk Address Packet (struktura dla int 13h AH=42h) ------
DAP:
    db 0x10                         ; rozmiar pakietu (zawsze 16)
    db 0                            ; zarezerwowane
    dw 0                            ; [+2] liczba sektorow
    dw 0                            ; [+4] offset bufora
    dw 0                            ; [+6] segment bufora
    dq 0                            ; [+8] LBA startowy (64-bit)

; -- Global Descriptor Table ---------------------------------
gdt_start:
    dq 0                            ; deskryptor NULL (wymagany)
gdt_code:                           ; 0x08 — segment kodu, caly 4 GB
    dw 0xFFFF                       ; limit 0-15
    dw 0x0000                       ; baza 0-15
    db 0x00                         ; baza 16-23
    db 10011010b                    ; dostep: kod, wykonywalny
    db 11001111b                    ; flagi + limit 16-19
    db 0x00                         ; baza 24-31
gdt_data:                           ; 0x10 — segment danych, caly 4 GB
    dw 0xFFFF
    dw 0x0000
    db 0x00
    db 10010010b                    ; dostep: dane, zapis
    db 11001111b
    db 0x00
gdt_end:

gdt_desc:
    dw gdt_end - gdt_start - 1      ; rozmiar GDT - 1
    dd gdt_start                    ; adres GDT

; ============================================================
;  TRYB CHRONIONY (32-BIT)
; ============================================================
[BITS 32]
pm_entry:
    mov ax, 0x10                    ; selektor segmentu danych
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x90000                ; nowy stos 32-bit

    ; -- potwierdzenie na ekranie (karta VGA tekstowa) ------
    mov esi, MSG_PM
    mov edi, 0xB8000                ; pamiec ekranu tekstowego
    mov ah, 0x0A                    ; kolor: jasnozielony na czarnym
.vga_loop:
    lodsb
    or al, al
    jz .vga_done
    mov [edi], ax
    add edi, 2
    jmp .vga_loop
.vga_done:

    ; -- parametry dla kernela -------------------------------
    mov ebx, 0x20000                ; EBX = fizyczny adres ZASZYFROWANEGO keystore
    mov ecx, 0x04D2                 ; ECX = magiczny znacznik "FENIX boot ok"

    jmp 0x08:0x10000                ; SKOK DO KERNELA — koniec pracy bootloadera

MSG_PM  db "FENIX OS protected mode - przekazuje sterowanie do kernela...", 0

; ------------------------------------------------------------
; wyzeruj reszte i dodaj sygnature bootowalnosci
; ------------------------------------------------------------
times 510 - ($ - $$) db 0
dw 0xAA55
