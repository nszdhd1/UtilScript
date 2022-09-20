import sys

import frida

device = frida.get_usb_device()
pid = device.spawn(["com.miHoYo.Yuanshen"])
session = device.attach(pid)
device.resume(pid)

scr = """
var APP_NAME = "com.miHoYo.Yuanshen"

var module = null;
while(module == null){
    module = Process.findModuleByName("libil2cpp.so");
}
send(module);

var unity = Process.findModuleByName("libunity.so");
send(unity);

var x = Interceptor.attach(ptr(unity.base).add(0xb2aecc),{
    onEnter:function(args){
    send(args[1]);
    },onLeave:function(ret){
       send(ret.sub(1).readUtf8String());

    }
});

Interceptor.attach(Module.findExportByName("libil2cpp.so","il2cpp_class_from_name"),{
    onEnter:function(args){
    //send(args[1].readUtf8String()  + "  -----  : "+args[2].readUtf8String());
    
    },onLeave:function(ret){
      
    }
});


// hook SetupMethodsLocked
var p_size = 8;
Interceptor.attach(ptr(module.base).add(0x72F09EC).add(0x204),{
    onEnter:function(args){
    var newMethod = this.context.x20
    var pointer = newMethod.readPointer();
    var name = newMethod.add(p_size * 2).readPointer().readCString();
    var klass = newMethod.add(p_size * 3).readPointer();
    var klass_name = klass.add(p_size * 2).readPointer().readCString();
    var klass_paze = klass.add(p_size * 3).readPointer().readCString();
    send(klass_paze+"."+klass_name+":"+name+"    -> "+pointer.sub(module.base));
    },onLeave:function(ret){
     
    }
});



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


