# 《Dive into Windbg系列》

* 作者：BlackINT3
* 联系：blackint3@gmail.com
* 网站：https://github.com/BlackINT3

> 《Dive into Windbg》是一系列关于如何理解和使用Windbg的文章，主要涵盖三个方面：
* 1、Windbg实战运用，排查资源占用、死锁、崩溃、蓝屏等，以解决各种实际问题为导向。
* 2、Windbg原理剖析，插件、脚本开发，剖析调试原理，便于较更好理解Windbg的工作机制。
* 3、Windbg后续思考，站在开发和逆向角度，谈谈软件开发，分享作者使用Windbg的一些经历。

## 第一篇 《Wireshark的卡死与崩溃》
> 涉及知识点：死锁与假死、SEH异常、崩溃分析、开源软件、PDB、Wireshark源码、Https、Qt信号槽、事件机制等。

## **起因**
    说起网络协议分析，首先想到的便是老牌的Wireshark，特点是跨平台、界面简洁易操作，协议齐全又开源。因此Wireshark久居网络安全工具排行榜前列，也当之无愧。然而笔者最近在使用Wireshark时，遇到了怪象，先是随机卡死，后又遭遇崩溃，本文主要讲述如何使用Windbg来分析这类问题。
## **寻找卡死的根源**
有一段时间没用Wireshark了，最近发现抓包一段时间后，Wireshark随机出现卡死，界面无响应。习惯性地升级版本，然而安装了新版2.4.3问题依旧，于是打算一探究竟。
  
![](https://p4.ssl.qhimg.com/t0177dc256525639c82.png)
首先界面无响应，多半是UI主线程卡死了,卡死主要有两种表现：
* 死锁：首先想到的便是哲学家用餐问题。Windows上常见的死锁是卡在等待内核对象上，比如事件、CRITICAL_SECITON（本质还是事件）、信号量、互斥体等。锁是并行编程常用的抽象概念，其实现多种多样。笔者也遇到过很多死锁问题，例如：

```  
  LdrpLoaderLock：临界区CRITICAL_SECTION，占用该锁地方很多。导致死锁的原因也很多，比如DllMain里创建线程，并等待线程退出。又比如调用GetModuleHandle等函数，操作PEB.LoaderList时，线程刚好被TerminateThread了，那么这个锁就永远占住了。排查这类问题常用命令!locks或者!cs（InitializeCriticalSection初始化时会用DebugInfo->ProcessLocksList把整个进程的临界区连起来，链表头是全局变量ntdll!RtlCriticalSectionList)，临界区结构里包含了许多有用信息，比如OwerThread、DebugInfo等等，输入dt -r _RTL_CRITICAL_SECTION查看。
  FileObjectLock：事件KEVENT，用同步操作I/O的要注意了。比如经常容易采坑的ZwQueryObject，当去查询一个同步的NamedPipe对象名称时，若NamedPipe处于ConnectNamedPipe状态（且没有Client连接进来），NtFsControlFile调用FSCTL_PIPE_LISTEN例程，而且NtFsControlFile也不会走FastIo流程，此时的Irp会阻塞，并且之前已经IopAcquireFastLock占用了FileObjectLock。所以ZwQueryObject查询这个FileObject便会导致死锁。
  AddressCreationLock：守护型互斥体KGUARDED_MUTEX。主要用于进程Vad树的同步操作。常见的死锁场景是当MmMapViewOfSection调用ImageLoad回调时，已经调用KeAcquireGuardedMutex占用了此锁，自然不能在回调里操作Vad，比如ZwAllocateVirtualMemory。
```

* 假死：现象和死锁相似，主要表现响应缓慢，也可能出现线程CPU占用高，例如大量循环、低效算法、同步I/O（读写文件、阻塞socket等），这类问题后面会讲述。

在开始分析前，需要先准备环境，因为笔者装的64位Wireshark，所以必须用Windbg X64版本调试，若分析dump则无此限制。设置微软官方符号后，快捷键F6附加到Wireshark.exe进程（若只需观察内存可以选择非侵入式Noninvasive）。Wireshark2.0开始UI从GTK换成Qt了，附加完成中断到DbgBreadkPoint后，输入~0k,查看Qt主线程栈回溯。
![](https://p4.ssl.qhimg.com/t01fbb1f93810d47312.png)

栈回溯犹为关键，通过观察，可得知几个信息：
  > Qt和libwireshark虽然没有PDB，但调用的函数大多都是导出函数，所以Windbg识别出了符号，注意观察符号后面的偏移地址，如果偏移太大，符号应该不正确，因为一个优雅的函数应该尽可能简洁。比如libwireshark!find_sid_name+0x6215f符号就是错误的。
 
  > 栈的最顶层并没有等待内核对象，整个调用都在用户态，说明用户态代码可能遇到了上文说的假死情况。

  > 卡死的可能是在调用dissector函数，即协议解码器。
  
当然，这只是一次线程栈的快照，并不能充分说明问题，为此，这里有个技巧就是构造多次线程快照，观察统计。对于这种必然卡死的问题可以F5（g）运行，再中断Ctrl+Break下来，重复几次，查看栈回溯。虽然每次栈最顶层都有变化，但是一直都离不开libwireshark!ssl_starttls_post_ack+0x6215这个Frame，说明八九不离十就是这个函数。

难道是解码TLS的数据卡住了？求解未知问题，方法很多，Windbg、IDA反汇编跟踪固然可以，但我们知道Wireshark是开源软件，因此对照源码分析更高效。而且对于一个正常项目来说，构建时必然会归档符号文件。于是笔者在https://www.wireshark.org/download/win64/all-versions/ 找到了2.4.3的PDB文件，同时下载了一份对应版本的源码。

说到PDB，经常有人会疑惑Windbg怎么老是加载不上符号，其实只需使用!sym noisy命令打印出Windbg的符号搜索过程，将对应的PDB复制到对搜索的路径，这里笔者直接将PDB释放到Wireshark目录,重新.reload一次，再次查看栈回溯。

![](https://p2.ssl.qhimg.com/t01e31c875e1132e27c.png)

感谢符号，有符号和没符号区别就是整容后和整容前的区别。由此看来，确实是TLS解码卡在了ssl_load_keyfile函数，因为这份PDB里包含了行号信息，直接找到对应的代码。

```
//packet-ssl-utils.c。
for (;;) {
    char buf[512], *line;
    gsize bytes_read;
    GMatchInfo *mi;

    line = fgets(buf, sizeof(buf), *keylog_file);
    if (!line)
        break;

    bytes_read = strlen(line);
    /* fgets includes the \n at the end of the line. */
    if (bytes_read > 0 && line[bytes_read - 1] == '\n') {
        line[bytes_read - 1] = 0;
        bytes_read--;
    }
    if (bytes_read > 0 && line[bytes_read - 1] == '\r') {
        line[bytes_read - 1] = 0;
        bytes_read--;
    }
    //....
    from_hex(pre_ms_or_ms, hex_pre_ms_or_ms, strlen(hex_pre_ms_or_ms));
    //....
```

不出所料，果然有一个大循环，每次循环调用fgets(buf, sizeof(buf), *keylog_file);读取512字节，即分块按行读取，猜测应该是keylog_file文件内容过多导致的了，到底是个什么文件？查看ssl_load_keyfile原型如下：
```
void
ssl_load_keyfile(const gchar *ssl_keylog_filename, FILE **keylog_file,
                 const ssl_master_key_map_t *mk_map)
```

现在问题转化为寻找key文件路径，也是寻找参数的过程，根据x64调用约定，前四个参数通过寄存器传递，后续参数通过栈传递。然而查看x64的前4个参数（rcx、rdx、r8、r9）并不容易（其余的的参数可通过栈帧找到），一般来说，前4个参数是通过反汇编分析上层或者下层函数，或者函数内部会暂存，总之需要分析反汇编代码间接找到。

第一个参数：文件路径。这个参数通过.frame、dv查看变量，但ssl_keylog_filename 显示 value unavailable，说明没推导出来。反汇编到上层调用函数，发现mov rcx,qword ptr [libwireshark!ssl_options+0x8]，参数rcx是一个全局变量，db poi(libwireshark!ssl_options+0x8)查看参数1的值，对应源码：
```
static ssl_common_options_t ssl_options = { NULL, NULL}; 
ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file, &ssl_master_key_map);
```

第二个参数：FILE**指针,crt的FILE可转换得到文件句柄，再通过句柄可找到对应的路径。_get_osfhandle函数手动转换方法：.frame 01切换到对应的frame上，再输入dv查看变量，这次推导出了keylog_file的值（这里的rdx一直暂存在r12中），根据导入表确定crt库：dqs libwireshark!_imp_fgets l1 得到ucrtbase!fgets，说明是Universal CRT（VS2015重构后的crt结构有所变化，具体可参考ucrt的源码），这里的FILE对应__crt_stdio_stream_data结构，其_file成员即是ioinfo的索引值。输入x ucrtbase!__pioinfo，查看ioinfo的地址，进而找到__crt_lowio_handle_data，根据偏移和索引值，可得到osfhnd，即文件句柄。然而!handle命令没法在用户态得到句柄对应的文件路径，可以写插件实现，也可以用procexp找到句柄对应的文件路径。
```
头文件：
ucrt\inc\corecrt_internal_stdio.h
struct __crt_stdio_stream_data
{
    union
    {
        FILE  _public_file;
        char* _ptr;
    };
    char*            _base;
    int              _cnt;
    long             _flags;
    long             _file;
    int              _charbuf;
    int              _bufsiz;
    char*            _tmpfname;
    CRITICAL_SECTION _lock;
};

头文件：ucrt\inc\corecrt_internal_lowio.h
//x64结构大小:0x40，osfhnd偏移:0x28，这些可通过sizeof打印，对于简单的结构体，偏移遵照对齐方式自行估算。
struct __crt_lowio_handle_data
{
    CRITICAL_SECTION           lock;
    intptr_t                   osfhnd;          // underlying OS file HANDLE
    __int64                    startpos;        // File position that matches buffer start
    unsigned char              osfile;          // Attributes of file (e.g., open in text mode?)
    __crt_lowio_text_mode      textmode;
    __crt_lowio_pipe_lookahead _pipe_lookahead;

    uint8_t unicode          : 1; // Was the file opened as unicode?
    uint8_t utf8translations : 1; // Buffer contains translations other than CRLF
    uint8_t dbcsBufferUsed   : 1; // Is the dbcsBuffer in use?
    char    dbcsBuffer;           // Buffer for the lead byte of DBCS when converting from DBCS to Unicode
};
typedef __crt_lowio_handle_data* __crt_lowio_handle_data_array[IOINFO_ARRAYS];
extern __crt_lowio_handle_data_array __pioinfo;
```

最后发现文件是"D:\ChromeSSL"，大小有100多M，看到chrome才回过神来，因为很早之前分析某网站的Https协议时，把chrome的ssl key通过环境变量SSLKEYLOGFILE存储到文件，再设置到了Pre-Master-Secret中。经过上述分析，卡死问题总算得解。。。

### **遭遇崩溃的尴尬**
刚解决完卡死问题，又遇到一次Wireshark崩溃。

![](https://p0.ssl.qhimg.com/t01ecc468ca3377fad2.png)

既然准备工作都完成了，那就接着分析吧。首先保存现场，存一份完整dump（minidump内存信息太少不易分析）。

说到如何转储dump，通常有几种方式：
```
procexp - Create Full/Mini Dump。
任务管理器 - 创建转储文件,完整dump。
Windbg - Attach到进程，.dump /ma c:\crash.dmp。这里有一点需要注意：如果是Attach上去再存储dump，那么当前的异常信息是Break instruction exception（用!analyze命令也分析不出真正的异常，后面我们会讲如何分析这类dump），因为此时程序正在等待WER服务响应，调试器并没有收到异常事件。正确做法是继续运行程序，在Werfault的错误框点击调试程序，若弹出选择VS JIT调试对话框，则选择否。Windbg会再次中断到异常状态，此时存储dump可获取到异常信息。
procdump - 命令行程序，跟procexp是一个系列。
自己写程序，调用MiniDumpWriteDump函数。一般软件都自带BugReport收集dump，而且dump里还加入了异常信息，具体可参考google breakpad实现。
```

笔者这次用Windbg保存了dump，将dump拖入windbg（x64/x86即可），输入.excr查看当前异常信息，发现是DbgBreakPoint(DbgUiRemoteBreakin)，也就是上面所提到的Attach int 3异常，异常信息虽有，但不正确。如果你用procexp、任务管理器存储的dump则会提示Unable to get exception context, HRESULT 0x80004002，因为这些程序在调用MiniDumpWriteDump函数生成dump时，没获取异常信息。

对于这类dump，可以用!analyze -v自动分析，或许能搜到异常信息。但笔者习惯先查看所有线程的栈回溯，输入：~* k，找到异常线程，如下：
```
00 00000000`00248c98 000007fe`fdae1430 ntdll!NtWaitForMultipleObjects+0xa
01 00000000`00248ca0 00000000`77991723 KERNELBASE!WaitForMultipleObjectsEx+0xe8
02 00000000`00248da0 00000000`77a0b5e5 kernel32!WaitForMultipleObjectsExImplementation+0xb3
03 00000000`00248e30 00000000`77a0b767 kernel32!WerpReportFaultInternal+0x215
04 00000000`00248ed0 00000000`77a0b7bf kernel32!WerpReportFault+0x77
05 00000000`00248f00 00000000`77a0b9dc kernel32!BasepReportFault+0x1f
06 00000000`00248f30 00000000`77b23398 kernel32!UnhandledExceptionFilter+0x1fc
07 00000000`00249010 00000000`77aa85c8 ntdll! ?? ::FNODOBFM::`string'+0x2365
08 00000000`00249040 00000000`77ab9d2d ntdll!_C_specific_handler+0x8c
09 00000000`002490b0 00000000`77aa91cf ntdll!RtlpExecuteHandlerForException+0xd
0a 00000000`002490e0 00000000`77ae1248 ntdll!RtlDispatchException+0x45a
0b 00000000`002497c0 00000001`3f9be2b1 ntdll!KiUserExceptionDispatch+0x2e
0c 00000000`00249ee0 00000001`3f9b97a4 Wireshark!rescan_packets+0x351 [c:\buildbot\wireshark\wireshark-2.4-64\windows-2016-x64\build\file.c @ 1773]
```

识别异常线程很简单，找关键函数KiUserExceptionDispatch，这是用户态SEH异常分发的源头，异常如果没人处理就到了UnhandledExceptionFilter，开始调用WerpReportFault函数，通过ALPC（\WindowsErrorReportingServicePort端口）发消息给WER服务弹错误提示，如果和WER服务通信失败，则创建Werfault.exe弹错误提示。创建Werfault再失败，就只有NtRaiseHardError，交给csrss弹框了（进程创建时，CsrCreateProcess时默认会设置EPROCESS的ExceptionPort，之间也交互是ALPC（\ApiPort端口）通信。

```
//Werfault进程的命令行参数-p是后面是异常进程ID。
//Werfault进程也会保存异常线程ID，对于多个同名进程，可以用procexp直接找到崩溃进程，查看异常线程的栈，粗略分析。
//下面是分析WerpReportFault得到的验证代码。
#define PAGE_SIZE 0x1000
HANDLE Section = (HANDLE)0x308;  //异常进程共享内存句柄，用procexp查看，一般是Werfault进程最后一个Section（procexp记得勾选显示uname handle）。
DWORD WerPid = 12304;      //Werfault进程ID
HANDLE WerProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, WerPid);
if (WerProcess != NULL) {
  BOOL DupOk;
  HANDLE DupHandle;
  //复制一份Section句柄
  DupOk = DuplicateHandle(WerProcess,Section,
    GetCurrentProcess(), &DupHandle,
    SECTION_MAP_READ, FALSE, 0);
  if (DupOk) {
    CHAR* MapBuffer;
    //访问共享内存，获取异常进程ID和线程ID
    MapBuffer = (CHAR*)MapViewOfFile(DupHandle, FILE_MAP_READ, 0 , 0, PAGE_SIZE);
    if (MapBuffer) {
      printf("Exception PID:%d\n", *(DWORD*)(MapBuffer+0x4));
      printf("Exception TID:%d\n", *(DWORD*)(MapBuffer+0x8));
      UnmapViewOfFile(MapBuffer);
    }
    CloseHandle(DupHandle);
  }
  CloseHandle(WerProcess);
}
```

通过Windbg找到异常线程后，如果dump中没保存异常信息，.excr不能用，怎么分析异常？很简单，从RtlDispatchException参数入手，函数原型如下：
```
BOOLEAN
RtlDispatchException (
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord
    )
```
前面提及过如何寻找x64的前4个参数，ub反汇编RtlDispatchException上层调用代码如下：
```
00000000`77ae1236 488bcc          mov     rcx,rsp
00000000`77ae1239 4881c1f0040000  add     rcx,4F0h
00000000`77ae1240 488bd4          mov     rdx,rsp
00000000`77ae1243 e8f87bfcff      call    ntdll!RtlDispatchException (00000000`77aa8e40)
```
说明ExceptionRecord=rcx=rsp+0x4F0，ContextFrame=rdx=rsp，继续查看0B栈帧，（.frame /r 0B或者~0kn查看栈帧SP）得到rsp的值，接着获取EXCEPTION_RECORD（.exr rsp+0x4F0），CONTEXT（.cxr rsp），使用dt命令亦可。

显示的异常指令：and dword ptr [rsi+24h],0FFFFFFFDh，rsi（96239a8）地址无效 。内存违规c0000005 (Access violation)是个很常见的错误，例如空指针、DoubleFree、UAF等。

根据这条异常信息猜测是一个结构成员的位标记，但结构体地址却无效，查看源码rescan_packets函数发现是fdata->flags.dependent_of_displayed = 0，而fdata地址无效。

capture_file cfile是个全局变量，用来管理数据包及状态，用dt命令结合符号查看。

```
0:000> dt wireshark!capture_file @@masm(wireshark!cfile)
   +0x000 epan             : (null) 
   +0x008 state            : 0 ( FILE_CLOSED )  //file已经关闭，即调用了cf_close，相应的内存都被释放。
```

为什么关闭？ 难道cfile有同步问题？带着这一系列问题阅读源码吧。

关于源码分析的一点说明：

首先选择一款好的源码阅读工具，比如SourceInsight、VisualStudioCode，VisualAssist，具备交叉引用，符号索引等实用。从开发入手，先熟悉软件架构，弄清代码结构及逻辑，追踪实现细节，通过代码交叉引用观察函数调用、参数传递等。从逆向入手，根据符号查看各种变量和内存结构，若函数没有符号（例如优化后的inline代码）那就需要多锻炼逆向分析能力了，熟悉调用约定，了解编译器常用优化。

必要时也可通过调试分析，依靠内存访问断点，结合栈回溯观察函数调用和参数传递。例如这里有个技巧通过Windbg调试新Wireshark实例，对state设置硬件写入断点：ba w4 @@c++(&wireshark!cfile.state)，可以观察到状态变化，通过栈回溯符号看到函数调用流程，能减轻不少工作量。

后续源码分析较为琐碎，考虑篇幅，因此我不再赘述，读者可自行阅读，最后结论是：

```
先看看cfile的文件状态
typedef enum {
  FILE_CLOSED,                  /* No file open */关闭状态
  FILE_READ_IN_PROGRESS,        /* Reading a file we've opened */抓包中，从管道读取数据
  FILE_READ_ABORTED,            /* Read aborted by user */用户异常终止
  FILE_READ_DONE                /* Read completed */停止抓包，读取完成
} file_state;
```
rescan_packets会定时调用update_progress_dlg更新进度条，更新进度条必然会刷新Qt UI，因此会调用WiresharkApplication::processEvents()准备处理UI事件，如果在此时触发了FILE_CLOSE事件就严重了。例如点了开始按钮，会调用on_actionCaptureStart_triggered函数，接着调用cf_close，释放了frames和fdata的内存，然后调用sync_pipe_start和dumpcap.exe通过管道接收捕获的数据包，然而接收数据是基于Qt定时器事件（周期为200ms），只有当收到第一份数据包时才会调用capture_input_new_file，进而调用cf_open更新state为FILE_READ_IN_PROCESS，才会为frames和fdata分配内存，因此这是导致崩溃的直接原因。

当然还有不少地方有这种问题，比如多次reload，再start，构造崩溃的极端方法如下：
```
1、先抓一部分数据包，然后点击停止。
2、多次按下Ctrl+R（reload），此时再按下E（start），即开始抓包。
3、这时程序会崩溃，或者一直按住Ctrl+R，再按E能稳定复现。
```
尝试了最新版的Wireshark 2.4.4也有此问题，整个分析过程就告一段落。

## **结束**

本文主要讲述了如何利用Windbg解决Wireshark卡死和崩溃此类实际问题，如果你也遇到过类似问题，不妨拿起Windbg去探一探究竟。

文章整体可能显得有些松散，有些是思维过程，有些是技巧，有些看似不相关。但我觉得对于学习和研究，可以试着走最长的路，看最远的风景，当你经历过看似繁琐的过程后，或许有不一样的思路。如果本文涉及的知识点我未详细说明的，各位可自行搜索研究，或者通过邮箱与我交流。

最后，感谢各位阅读，期待下次再见。

```
参考资料：
Google
MSDN
Qt Assist
Windbg Help
WRK/NT/Windows 2000 source code
```
