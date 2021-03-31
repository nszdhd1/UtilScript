import idaapi
import idautils

def decompile(func):
    try:
        func_str = idaapi.decompile(func)
    except:
        return " decompile faild \n"
    return str(func_str)

def main():
    if not idaapi.init_hexrays_plugin():
        return False
    output = GetInputFile().split('.')[0]+'.cpp'
    f = open(output,'a')
    for segea in Segments():
        for funcea in idautils.Functions(segea, SegEnd(segea)):
            code = decompile(funcea)
            f.write(code)
    f.close()

if main():
    idaapi.term_hexrays_plugin()





