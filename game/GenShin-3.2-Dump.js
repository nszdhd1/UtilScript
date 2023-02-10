let so = Process.findModuleByName("libil2cpp.so")
let il2cpp_method_get_name = new NativeFunction(so.base.add(0x4260354),'pointer',['pointer'])
let il2cpp_method_get_param = new NativeFunction(so.base.add(0x425FEC4),'pointer',['pointer','int'])
let il2cpp_method_get_return_type = new NativeFunction(so.base.add(0x42306EC),'pointer',['pointer'])
 
let il2cpp_class_from_type = new NativeFunction(so.base.add(0x4251ED8),'pointer',['pointer'])
let il2cpp_class_get_name  = new NativeFunction(so.base.add(0x4252E48),'pointer',['pointer'])
 
 
Interceptor.attach(so.base.add(0x4252BE4),{
    onEnter:function (args) {
        // console.log("---------il2cpp_class_get_methods--------")
        this.class = args[0]
 
    },
    onLeave:function (ret) {
        try{
            let classname = this.class.add(40).readPointer().readCString()
            let namespace = this.class.add(120).readPointer().readCString()
            let name_ptr = il2cpp_method_get_name(ret)
            let ret_type = il2cpp_method_get_return_type(ret)
            let ret_type_class = il2cpp_class_from_type(ret_type)
            let ret_class_name = il2cpp_class_get_name(ret_type_class)
 
            //InvokerMethod ret.add(16)  methodPointer ret
             let parameters_count = ret.add(50).readU8()
            let pstr = "("
            for(let idx = 0;idx<parameters_count;idx++){
                let param = il2cpp_method_get_param(ret,idx)
                let type = il2cpp_class_from_type(param)
                let typeName = il2cpp_class_get_name(type)
                pstr += ptr(typeName).readCString() + "  a"+idx +" ,"
            }
            pstr+=");"
            console.log("[*]"+ret.readPointer()+"   --> "+ptr(ret_class_name).readCString()+"  "+namespace+"."+classname+"."+ptr(name_ptr).readCString()+pstr)
 
        }catch (e) {
            console.log(e.toString())
        }
 
    }
})