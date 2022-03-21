var lua_State = null
const LUA_PATH = "/data/data/packagename/luadump"
const APP_DIR = "/data/data/packagename"
var luaL_loadfilex,luaL_loadstring,lua_pcall,lua_tolstring,luaL_loadbufferx,LuaEnv



// 作者说只支持art
// Java.performNow(function (){
//     var FileObserver = Java.use("android.os.FileObserver");
//     var LuaFileObserver = Java.registerClass({
//         name:'com.hotfix.LuaFileObserver',
//         superClass:FileObserver,
//         implements: [FileObserver],
//         methods:{
//             $init:[{
//                 returnType: 'void',
//                 arguments:['java.lang.String'],
//                 implementation:function (p){
//                     this.$super.$init(p)
//                 }
//             }, {
//                     returnType: 'void',
//                     arguments:[''],
//                     implementation:function (){
//                         this.$super.$init()
//                     }
//                 }],
//             $new:{
//                 returnType: 'void',
//                 arguments:['java.lang.String'],
//                 implementation:function (p){
//                     this.$super.$new(p)
//                 }
//             },
//             // onEvent:{
//             //         returnType: 'void',
//             //         arguments:['int','java.lang.String'],
//             //         implementation:function(event,path){
//             //         console.log("event :"+event)
//             //         console.log("path :"+path)
//             //     }
//             // },
//             stopWatching:{
//                 returnType: 'void',
//                 arguments:[''],
//                 implementation:function (){
//                     this.$super.stopWatching()
//                 }
//             },
//             startWatching:{
//                 returnType: 'void',
//                 arguments:[''],
//                 implementation:function (){
//                     this.$super.stopWatching()
//                 }
//             },
//             finalize:{
//                 returnType: 'void',
//                 arguments:[''],
//                 implementation:function (){
//                     this.$super.stopWatching()
//                 }
//             },
//             onEvent:function(event,path){
//                 console.log("event :"+event)
//                 console.log("path :"+path)
//             }
//
//         }
//     });
//     var FileWatcher = LuaFileObserver.$new(LUA_PATH)
//     FileObserver.onEvent.implementation = function (event,path){
//         console.log("event :"+event)
//         console.log("path :"+path)
//     }
//     FileWatcher.startWatching()
// })
var  gettid = new NativeFunction(Module.findExportByName(null,"gettid"),'int',[])

var status = 0

function LuaFileWatcher(){

    var pthread_mutex_init = new NativeFunction(Module.findExportByName(null,"pthread_mutex_init"),'int',['pointer','pointer'])
    var pthread_mutex_lock = new NativeFunction(Module.findExportByName(null,"pthread_mutex_lock"),'int',['pointer'])
    var pthread_mutex_unlock = new NativeFunction(Module.findExportByName(null,"pthread_mutex_unlock"),'int',['pointer'])

    var inotify_init = new NativeFunction(Module.findExportByName(null,"inotify_init"),'int',[])
    var inotify_add_watch = new NativeFunction(Module.findExportByName(null,"inotify_add_watch"),'int',['int','pointer','int'])
    const read = new NativeFunction(Module.findExportByName(null,"read"),'int',['int','pointer','int']);
    var fd = inotify_init()
    var wd = inotify_add_watch(fd,Memory.allocUtf8String(LUA_PATH),256) //ALL_EVENTS = 4095,OPEN=32
    console.log("fd "+fd+",wd "+wd)
    const inotify_event_len = 0x10
    var data = Memory.alloc(inotify_event_len*10);
    while (1){
        let readlen = read(fd,data,inotify_event_len*10-1)
        if( readlen<0){
            console.log('[+] Unable to read  [!] ');
            continue
        }
        console.log(readlen,data)

        // struct inotify_event {
        //     __s32 wd;
        //     __u32 ;
        //     __u32 cookie;
        //     __u32 len;
        //     char name[0];
        // };
        for (let i = 0; i < (readlen/0x10) ; i++) {
            let readData = data.add(i*0x10)
            let envent = []
            envent.wd = readData.readS32();
            envent.mask = readData.add(4).readU32();
            envent.cookie = readData.add(8).readU32();
            envent.len = readData.add(12).readU32();
            envent.name = readData.add(16).readCString();
            console.log('open file : ',envent.name,envent.mask)
            if(envent.mask!=256)
                continue;
                var mutex = Memory.alloc(Process.pointerSize)
                pthread_mutex_init(mutex,new NativePointer(0))
                 console.log("run thread pid "+Process.id +" run "+gettid())
                pthread_mutex_lock(mutex)

                try{
                    status = 1
                    console.log('----------------------')
                    let luaname = envent.name.replaceAll("_",".")
                    console.log("luaname"+luaname)
                    var scr ='if string.find(package.path,"/data/data/package_name/luadump/") == nil then\n' +
                        '    package.path = package.path .. ";/data/data/package_name/luadump/?"\n' +
                        'end\n'+
                        'require(\"HotFixOOOK\")\n'+
                        'hotfix(\"'+luaname+'\")'
                    var luaL_loadstring_ret = luaL_loadstring(lua_State,Memory.allocUtf8String(scr))
                    console.log("luaL_loadstring_ret  : "+luaL_loadstring_ret)
                    send("load lua init ret "+ lua_pcall(lua_State,0,0,0) + "  str:"+lua_tolstring(lua_State, -1).readCString())

                }catch (e) {
                    send("err:"+e.toString())
                }finally {
                    pthread_mutex_unlock(mutex)
                    status = 0
                }

        }

    }

}

var  pthread_create = new NativeFunction(Module.findExportByName(null,"pthread_create"),'int',['pointer','pointer','pointer','pointer'])
var  pthread_join = new NativeFunction(Module.findExportByName(null,"pthread_join"),'int',['pointer','pointer'])
var LuaFileWatcherNative = new NativeCallback(LuaFileWatcher,'void',['void'])


// 启动新线程对目标目录进行文件监控。
var pthread_t = Memory.alloc(16).writeLong(0)
pthread_create(pthread_t,new NativePointer(0),LuaFileWatcherNative,new NativePointer(0))
console.log("run pthread_create pid "+Process.id +" run "+gettid())


var libil2cpp = null;
while(libil2cpp == null){
    libil2cpp = Process.findModuleByName("libil2cpp.so");
}
send(libil2cpp);

var module = null;
while(module == null){
    module = Process.findModuleByName("libxlua.so");
}
send(module);

Interceptor.attach(Module.findExportByName("libxlua.so","luaL_loadbufferx"),{
    onEnter:function(args){
        const name = Memory.readCString(args[3]);
        console.log("luaL_loadbufferx  name :",name)
    }
});



Interceptor.attach(Module.findExportByName("libxlua.so","luaL_openlibs"),{
    onEnter:function(args){
        send("lua_State:"+args[0])
        lua_State = ptr(args[0])
        luaL_loadfilex = new NativeFunction(Module.findExportByName("libxlua.so","luaL_loadfilex"),'int',['pointer','pointer'])
        luaL_loadstring = new NativeFunction(Module.findExportByName("libxlua.so","luaL_loadstring"),'int',['pointer','pointer'])
        lua_pcall = new NativeFunction(Module.findExportByName("libxlua.so","lua_pcall"),'int',['pointer','int','int','int'])
        lua_tolstring = new NativeFunction(Module.findExportByName("libxlua.so","lua_tolstring"),'pointer',['pointer','int'])

        luaL_loadbufferx = new NativeFunction(Module.findExportByName("libxlua.so","luaL_loadbufferx"),'int',['pointer','pointer','int','pointer','pointer'])

    },onLeave:function (ret) {
    }
});


