# encoding: UTF-8

import sys
import frida

"""
     该脚本用于dump cocos 使用的 lua 脚本
     dump 文件保存在 /sdcard/fridadump文件夹中，
     如果 fridadump 文件夹中存在lua文件，就会加载fridadump中的lua文件
     游戏安全测试好帮手，(#^.^#)
"""

device = frida.get_usb_device()
pid = device.spawn(["com.nayijian.guanwang"])
session = device.attach(pid)
device.resume(pid)

scr = """
var APP_NAME = "com.nayijian.guanwang"

var module = null;
while(module == null){
    module = Process.findModuleByName("libil2cpp.so");
}
send(module);

Interceptor.attach(Module.findExportByName(null,"luaL_loadbufferx"),{
    onEnter:function(args){
        var name = Memory.readCString(args[3]);
        send(name.length);
        if(name.length < 50){
            send(name);

            this.Path = name.substring(0,name.lastIndexOf("/"));
            this.file = name.substring(name.lastIndexOf("/")+1,name.length);
            if(access("/sdcard/fridadump/lua/"+this.Path) == -1){ //文件夹不存在
                folder_mkdirs(this.Path);               
            }
            if(access("/sdcard/fridadump/lua/"+name) == 0 ){//文件存在
                var data = read_lua("/sdcard/fridadump/lua/"+name);
                send(data);
                args[1] = data.data;
                args[2] = new NativePointer(ptr(data.size));
                send("do load file :" + name);
                
            }else{
                Dump("/sdcard/fridadump/lua/"+name,args[1],args[2].toInt32());
            }
            
        }

    }
});

function Dump(filePath,data,datalen){
    send("dump  : "+ filePath);
    var dumpfile = new File(filePath,"wb"); 
    dumpfile.write(data.readByteArray(datalen));
    dumpfile.close();
}

function access(filePath){
    var ptr_access = Module.findExportByName("libc.so","access");
    var func_access = new NativeFunction(ptr_access,'int',['pointer','int']);
    var ptr_filepath = Memory.allocUtf8String(filePath);
    var ret = func_access(ptr_filepath,0);
    return ret;
}

function mkdir(Path){
    var ptr_mkdir = Module.findExportByName("libc.so","mkdir");
    var func_mkdir = new NativeFunction(ptr_mkdir,'int',['pointer','int']);
    var ptr_filepath = Memory.allocUtf8String(Path);
    var ret = func_mkdir(ptr_filepath,777);
    return ret;
}

function folder_mkdirs(p){
    var p_list = p.split("/");
    var pp = "/sdcard/fridadump/lua";
    for(var i = 0;i< p_list.length  ;i++){
        pp = pp + "/" + p_list[i];
        if(access(pp) != 0){
            var x = mkdir(pp)
            send("mkdir :"+pp+"ret :" +x);
        }
    }
    
}
// frida file 对象没有read 
function read_lua(filePath){
    var ptr_open = Module.findExportByName("libc.so","open");
    const open = new NativeFunction(ptr_open,'int',['pointer','int']);

    var ptr_read = Module.findExportByName("libc.so","read");
    const read = new NativeFunction(ptr_read,'int',['int','pointer','int']);

    var ptr_close = Module.findExportByName("libc.so","close");
    const close = new NativeFunction(ptr_close,'int',['int']);

    var fd = open(Memory.allocUtf8String(filePath),0);
    var size = get_file_size(fd);
    if(size >0){
        var data = Memory.alloc(size + 5);
        if( read(fd,data,size) <0){
            console.log('[+] Unable to read DLL [!]');
            close(fd);
            return 0;
        }
        close(fd);
        return {data:data,size:size};
    }

}

function get_file_size(fd){
    var statBuff = Memory.alloc(500);
    var fstatSymbol = Module.findExportByName('libc.so', 'fstat');
    var fstat = new NativeFunction(fstatSymbol, 'int', ['int', 'pointer']);
    if(fd > 0) {
        var ret = fstat(fd, statBuff);
        if(ret < 0) { console.log('[+] fstat --> failed [!]');
        }
    }
    var size = Memory.readS32(statBuff.add(0x30));
    if(size > 0) {
            return size;
        } else {
            return 0;
    }
}

"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


script = session.create_script(scr)
script.on("message", on_message)
script.load()
sys.stdin.read()


