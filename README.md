# UtilScript

frida  赛高~ o(￣▽￣)ｄ

## game 

yuansheninject.py 是喵喵子的 [使用frida获取unity il2cpp符号信息](https://nszdhd1.github.io/2020/12/04/%E4%BD%BF%E7%94%A8frida%E8%8E%B7%E5%8F%96il2cpp%E7%AC%A6%E5%8F%B7%E4%BF%A1%E6%81%AF/#more) 里的代码 

exportCode.py 是ida 导出伪代码到 cpp文件里

## InjectFrida

[非root环境下frida持久化的两种方式及脚本](https://bbs.pediy.com/thread-268175.htm)

使用方法：
   python3 script.py 需要注入的apk  输出路径（注意结尾不要添加/） 注入so的名字（最好是第一个加载的） 
            -apksign（可选项，写了就一键签名） -persistence(反正只多一个config文件，最好加上)