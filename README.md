# UtilScript

frida  赛高~ o(￣▽￣)ｄ

## game 

一些脚本：

Frida-cocos-lua-dump.py dump cocos游戏的lua代码

Frida-mono-dump.py dump unity mono 的dll

yuansheninject.py 是喵喵子的 [使用frida获取unity il2cpp符号信息](https://nszdhd1.github.io/2020/12/04/%E4%BD%BF%E7%94%A8frida%E8%8E%B7%E5%8F%96il2cpp%E7%AC%A6%E5%8F%B7%E4%BF%A1%E6%81%AF/#more) 里的代码 

exportCode.py 是ida 导出伪代码到 cpp文件里

GGHook.js 用户获取GG脚本运行时的相关信息 [GameGuardian的Lua脚本分析](https://nszdhd1.github.io/2022/09/08/GameGuardian%E7%9A%84Lua%E8%84%9A%E6%9C%AC%E6%B7%B7%E6%B7%86%E5%88%86%E6%9E%90/#more)

GenShin-3.2-Dump.js 原神3.2版本符号信息dump [IL2CPP runtime dump](https://bbs.pediy.com/thread-275146.htm)

## InjectFrida

frida注入apk的两种实现方式：

[非root环境下frida持久化的两种方式及脚本](https://bbs.pediy.com/thread-268175.htm)

使用方法：
python3 script.py 需要注入的apk  输出路径（注意结尾不要添加/） 注入so的名字（最好是第一个加载的） apksign（可选项，写了就一键签名） -persistence(反正只多一个config文件，最好加上)

## lua

GGInjector64.lua  使用 gameguardian lua脚本 实现64位elf文件解析