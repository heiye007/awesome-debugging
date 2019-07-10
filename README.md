# awesome-debugging
Thinking：Why Debugging?（思考：为什么要调试？）

### Introduction - 简介
* 调试（Debugging），是一门学问，一门技术，一不小心掉进深渊无法生还。
* 话说盘古开天之时，调试界有三种人：
  * 推崇者：调试介于牛A和牛C之间...这样..那样..然后..Breakpoint/CallStacks/Step/Trace...此处省略一万字...
  * 鄙视者：一来就调试，不从问题本身、架构设计去思考，缺少思维实验，手速快思想狭隘。
  * 吃瓜者：不明觉厉...
* Why Debugging? 
  * 整个项目会围绕这个论题展开，五味杂陈皆聚于此。
  * 项目会沉积一些有用的工具、书、网站、话题、文章、以及分享作者自身的经历和思考。

### Debuggers - 调试器
* [Windbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)
  * Windows官方调试器，牛逼不接受反驳。
  * 《Dive Into Windbg》
    * [1-Wireshark卡死与崩溃](windbg/dive-into-windbg/1-Wireshark卡死与崩溃/1-Wireshark卡死与崩溃.md)
    * [2-AudioSrv音频服务故障](windbg/dive-into-windbg/2-AudioSrv音频服务故障/2-AudioSrv音频服务故障.md)
    * [3-Explorer无法启动排查](windbg/dive-into-windbg/3-Explorer无法启动排查/3-Explorer无法启动排查.md)
    * [4-Windbg脚本与插件](windbg/dive-into-windbg/4-Windbg脚本与插件/4-Windbg脚本与插件.md)

* [x64dbg](https://github.com/x64dbg/x64dbg)/[Ollydbg](http://www.ollydbg.de/)
  * Ollydbg，人称OD，驰骋江湖多年，OD之所以能流行很大程度上依赖于它的插件生态圈，当然可操作性也是没话说。x64dbg，在开源世界里疯狂生长。只能说长江后浪推前浪，一浪更比一浪强。
  * [TODO]

* [gdb](https://www.gnu.org/software/gdb/)
  * GNU Debugger，*nix系列调试器，当然也可调试PE，不过Windows系统下还是用标准的吧。
  * [TODO]

* [lldb](https://lldb.llvm.org/)
  * LLVM项目调试器，Android/iOS/MacOS开发逆向必备，常用于调试Mach-O。
  * [TODO] 

* [dlv](https://github.com/go-delve/delve)
  * dlv，全名delve，是为Go语言量身打造的一款调试器。
  * [TODO]

* [v8-debugger](https://v8.dev/docs/inspector)
  * v8调试器，带上inspector，调试Nodejs更方便。
  * [TODO]

* 其它
  * [CMDebug](https://jpsoft.com/all-downloads/downloads.html) - 批处理调试器，收费版

### Books - 书籍
* 《Windows高级调试 Advanced Windows Debugging》
* 《Inside Windows Debugging》
* 《软件调试》
* [delve Internal Architecture](dlv/delve_Internal_Architecture.pdf)

### Webs - 网站
* [TODO]

### Contributions
* 欢迎提交