import os
import sys
import frida


"""
    该脚本用于dump unity mono 的dll，
    dll 未保护 使用  mono_image_open_from_data_with_name，
    dll 被保护（加密，主要是TX），使用 do_mono_image_load,这是一个非导出函数，在libmono.so搜索字符串 “data-%p”即可。
    具体原因及讲解见大佬18年帖子：https://bbs.pediy.com/thread-247487.htm
    
    ps.
    需要 手动创建 两个文件夹
    1. /sdcard/fridadump  2. /data/data/app_anme/frida

"""

APP_NAME = "com.tencent.pocket"

def pull_dll():
    inpath = pulldir = "/data/data/" + APP_NAME + "/frida"
    cmd_cp = "adb shell su -c 'cp -r " + inpath + " /sdcard/fridadump ' "
    print(cmd_cp)
    cmd_pull = "adb pull /sdcard/fridadump"
    os.system(cmd_cp)
    os.system(cmd_pull)


def push_dll():
    path = "/data/data/" + APP_NAME
    cmd_push = "adb push fridadump /sdcard"
    cmd_cp = " adb shell su -c 'cp -r /sdcard/fridadump/frida " + path +" '"
    print(cmd_cp)
    os.system(cmd_push)
    os.system(cmd_cp)




device = frida.get_usb_device()
pid = device.spawn(["com.DefaultCompany.unity2020"])
session = device.attach(pid)
device.resume(pid)

scr = """
var DUMP_FILE_PATH = "/data/data/com.tencent.pocket/frida/";
var APP_NAME = "com.tencent.pocket"
function DumpDll(filePath,data,datalen){

    send("dump dll : "+ filePath);
    var dumpfile = new File(filePath,"wb");
    dumpfile.write(data.readByteArray(datalen));
    dumpfile.close();

}


Interceptor.attach(Module.findExportByName(null , "dlopen"), {
    onEnter: function(args) {
        var soName = args[0].readCString();
        if(soName.indexOf(APP_NAME) != -1 && soName.indexOf("libmono.so") != -1){
            send("dlopen load :"+soName);
            this.hook = true;
        }
    },
    onLeave:function(retval){
            if(this.hook == true){
                do_image_hook();
            }
    }
});


function do_image_hook(){

var module = Process.getModuleByName("libmono.so");
send(module.base);
Interceptor.attach(ptr(module.base).add(0x194878),{ //do_mono_image_load()
    onEnter:function(args){
        var images = args[0];
        var name = images.add(20).readPointer().readCString();
        var data = images.add(8).readPointer();
        var length = images.add(12).readPointer()

        send(name);
        send(length);
         var s = name.split("/");
         var filePath = DUMP_FILE_PATH + s[s.length -1];
        DumpDll(filePath,data,length.toInt32());

    }

});

Interceptor.attach(Module.findExportByName("libmono.so","mono_image_open_from_data_with_name"),{
        onEnter:function(args){

            var s = args[5].readCString().split("/");
            var filePath = DUMP_FILE_PATH + s[s.length -1];

            
               // DumpDll(filePath,args[0],args[1].toInt32());
                
         

        }
    });

}

function Check_dump_file(filePath){

    var ptr_access = Module.findExportByName("libc.so","access");
    var func_access = new NativeFunction(ptr_access,'int',['pointer','int']);
    var ptr_filepath = Memory.allocUtf8String(filePath);
    var ret = func_access(ptr_filepath,0);
    return ret;
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

// frida file 对象没有read
function do_load_dll(filePath){
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
        return data;
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



