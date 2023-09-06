# level0

- We login as user level0, this is then displayed:
```
GCC stack protector support:            Enabled
Strict user copy checks:                Disabled
Restrict /dev/mem access:               Enabled
Restrict /dev/kmem access:              Enabled
grsecurity / PaX: No GRKERNSEC
Kernel Heap Hardening: No KERNHEAP
System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
```

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/level0/level0
```

- The first block is related to various security measures, usually at the operating system or compiler level, that can impact the way programs are executed: [GCC stack protector](https://lwn.net/Articles/584225/) support, [strict user copy checks](https://cateee.net/lkddb/web-lkddb/DEBUG_STRICT_USER_COPY_CHECKS.html), [/dev/mem and /dev/kmem](https://man7.org/linux/man-pages/man4/mem.4.html) access, [grsecurity](https://fr.wikipedia.org/wiki/Grsecurity) and [PaX](https://fr.wikipedia.org/wiki/PaX) settings, [Kernel Heap Hardening](https://www.timesys.com/security/securing-your-linux-configuration-kernel-hardening/) and [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization).


- The second block is about the binary we need to exploit. Here we can see informations about the use of [RELRO](https://www.redhat.com/fr/blog/hardening-elf-binaries-using-relocation-read-only-relro), [stack canary](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries), [NX bit](https://en.wikipedia.org/wiki/NX_bit), [PIE](https://en.wikipedia.org/wiki/Position-independent_code), and other informations like if the executable uses relative paths to find shared libraries.


- We need the flag for the next level, which is written in a file located in the home directory of the user of the next level.
```
level0@RainFall:~$ ls -l
total 732
-rwsr-x---+ 1 level1 users 747441 Mar  6  2016 level0
```


- A binary has been left for us, it belongs to the user of the next level. Additionally, [the setuid and setgid permission bits](https://en.wikipedia.org/wiki/Setuid) are set.
Thus, this binary is executed with the privileges of user level1.
Let's take a closer look at this binary using [GDB](https://en.wikipedia.org/wiki/GNU_Debugger).
```
level0@RainFall:~$ gdb level0
...
(gdb) disas main
Dump of assembler code for function main:
   0x08048ec0 <+0>:     push   %ebp
   0x08048ec1 <+1>:     mov    %esp,%ebp
   0x08048ec3 <+3>:     and    $0xfffffff0,%esp
   0x08048ec6 <+6>:     sub    $0x20,%esp
   0x08048ec9 <+9>:     mov    0xc(%ebp),%eax
   0x08048ecc <+12>:    add    $0x4,%eax
   0x08048ecf <+15>:    mov    (%eax),%eax
   0x08048ed1 <+17>:    mov    %eax,(%esp)
   0x08048ed4 <+20>:    call   0x8049710 <atoi>
   0x08048ed9 <+25>:    cmp    $0x1a7,%eax
   0x08048ede <+30>:    jne    0x8048f58 <main+152>
   0x08048ee0 <+32>:    movl   $0x80c5348,(%esp)
   0x08048ee7 <+39>:    call   0x8050bf0 <strdup>
   0x08048eec <+44>:    mov    %eax,0x10(%esp)
   0x08048ef0 <+48>:    movl   $0x0,0x14(%esp)
   0x08048ef8 <+56>:    call   0x8054680 <getegid>
   0x08048efd <+61>:    mov    %eax,0x1c(%esp)
   0x08048f01 <+65>:    call   0x8054670 <geteuid>
   0x08048f06 <+70>:    mov    %eax,0x18(%esp)
   0x08048f0a <+74>:    mov    0x1c(%esp),%eax
   0x08048f0e <+78>:    mov    %eax,0x8(%esp)
   0x08048f12 <+82>:    mov    0x1c(%esp),%eax
   0x08048f16 <+86>:    mov    %eax,0x4(%esp)
   0x08048f1a <+90>:    mov    0x1c(%esp),%eax
   0x08048f1e <+94>:    mov    %eax,(%esp)
   0x08048f21 <+97>:    call   0x8054700 <setresgid>
   0x08048f26 <+102>:   mov    0x18(%esp),%eax
   0x08048f2a <+106>:   mov    %eax,0x8(%esp)
   0x08048f2e <+110>:   mov    0x18(%esp),%eax
   0x08048f32 <+114>:   mov    %eax,0x4(%esp)
   0x08048f36 <+118>:   mov    0x18(%esp),%eax
   0x08048f3a <+122>:   mov    %eax,(%esp)
   0x08048f3d <+125>:   call   0x8054690 <setresuid>
   0x08048f42 <+130>:   lea    0x10(%esp),%eax
   0x08048f46 <+134>:   mov    %eax,0x4(%esp)
   0x08048f4a <+138>:   movl   $0x80c5348,(%esp)
   0x08048f51 <+145>:   call   0x8054640 <execv>
   0x08048f56 <+150>:   jmp    0x8048f80 <main+192>
   0x08048f58 <+152>:   mov    0x80ee170,%eax
   0x08048f5d <+157>:   mov    %eax,%edx
   0x08048f5f <+159>:   mov    $0x80c5350,%eax
   0x08048f64 <+164>:   mov    %edx,0xc(%esp)
   0x08048f68 <+168>:   movl   $0x5,0x8(%esp)
   0x08048f70 <+176>:   movl   $0x1,0x4(%esp)
   0x08048f78 <+184>:   mov    %eax,(%esp)
   0x08048f7b <+187>:   call   0x804a230 <fwrite>
   0x08048f80 <+192>:   mov    $0x0,%eax
   0x08048f85 <+197>:   leave
   0x08048f86 <+198>:   ret
End of assembler dump.
```


- We can see that the program moves values onto the stack to prepare for a call to `<atoi>` (probably one of the parameters the program takes). The return of `<atoi>` is then compared to the hexadecimal value 1a7 (423) to determine the sequence of instructions to execute. In case the two values are not equal, we attempt to `<fwrite>` something before exiting.
In the other case, call `<execv>` with the value located at `0x80c5348` as a parameter:
```
(gdb) x/s 0x80c5348
0x80c5348:       "/bin/sh"
```


- Thus:
```
level0@RainFall:~$ ./level 423
$ whoami
level1
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
$ exit
```


- Fairly simple.
```
level0@RainFall:~$ su level1
Password:1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
level1@RainFall:~$
```
