# Hand-rolled x86_64 static-PIE — non-Go test fixture for Stage E.
#
# Build (see Makefile):
#   gcc -static-pie -nostdlib -fno-asynchronous-unwind-tables \
#       -o hello_static_pie_c hello_static_pie_c.s
#
# Bypasses libc entirely: write(stdout, msg, 19) + exit_group(0)
# via raw amd64 Linux syscalls. Produces an ELF64 ET_DYN with no
# DT_NEEDED, no .go.buildinfo — the Stage E gate's broadened
# contract (any self-contained ET_DYN) accepts it.
#
# Why hand-rolled rather than a minimal C "hello world": this
# repo's build host (Fedora) lacks `glibc-static`, which a
# real -static-pie C binary requires to link. The asm fixture
# reproduces the structural shape of any non-Go static-PIE
# without taking a system dependency.

.intel_syntax noprefix
.global _start
.section .text

_start:
    # write(1, msg, 19)
    mov rax, 1            # SYS_write
    mov rdi, 1            # fd = stdout
    lea rsi, [rip+msg]    # buffer
    mov rdx, 19           # length (matches "hello from raw asm\n")
    syscall

    # exit_group(0) — same as Go's runtime.exit; kernel kills the
    # whole process. The reflective loader's parent dies with us.
    mov rax, 231          # SYS_exit_group
    xor rdi, rdi          # status = 0
    syscall

# Inline message — kept inside .text so .equ-based length math
# works without cross-section linker subtleties (cf. the path
# that originally produced a zero-length write).
msg:
    .ascii "hello from raw asm\n"
