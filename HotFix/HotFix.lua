
--package.cpath = package.cpath .. ';C:/Users/lenovo/.Rider2018.3/config/plugins/intellij-emmylua/classes/debugger/emmy/windows/x64/?.dll'
function print_func_ref_by_csharp()
    local registry = debug.getregistry()
    for k, v in pairs(registry) do
        if type(k) == 'number' and type(v) == 'function' and registry[v] == k then
            local info = debug.getinfo(v)
            ReleaseLogger.Log("[oook]", "[HotFix]", "[print_func_ref_by_csharp]",string.format('%s:%d', info.short_src, info.linedefined))
        end
    end
end
function hotfix(filename)
    --print_func_ref_by_csharp()
    ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]","start hotfix: "..filename)
    --local dumpname = string.gsub(filename,"%.","_")
    local dumpname = filename
    local oldModule
    if package.loaded[filename] then
        oldModule = package.loaded[filename]
    elseif package.loaded[dumpname] then
        oldModule = package.loaded[dumpname]
    else
        ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]",'this file nevev loaded: '..filename)
        return
    end

    package.loaded[filename] = nil
    package.loaded[dumpname] = nil

    local ok,err = pcall(require, dumpname)
    if not ok then
        package.loaded[filename] = oldModule
        ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]",'reload lua file failed:'..err)
        return
    end


    ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]",'loaded newMpdule '..dumpname..' ,oldModule: '..filename)
    local newModule = package.loaded[dumpname]

    if newModule == nil then
        -- try again
        require(dumpname)
        newModule = package.loaded[dumpname]
    end


    ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]",'oldModule: '.. tostring(oldModule)..' ,newModule: '..tostring(newModule))

   --
   --
   -- if newModule == nil then
   --     package.loaded[filename] = oldModule
   --     ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]",'replaced faild !! ')
   --     return
   -- end
   --local updated_tables = {}
   -- ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]","updated_tables:"..type(oldModule).." new:"..type(newModule))
   -- --update_table(newModule, oldModule,updated_tables)
   -- ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]","7")
   --
   -- package.loaded[filename] = newModule

    ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]",'replaced succeed')

end

function ResetENV(object, name)
    local visited = {}
    local function f(object, name)
        if not object or visited[object] then return end
        visited[object] = true
        if type(object) == "function" then
            xpcall(function () setfenv(object, _G) end, CS.UnityEngine.Debug.LogError)
        elseif type(object) == "table" then
            for k, v in pairs(object) do
                f(k, tostring(k).."__key" )
                f(v, tostring(k))
            end
        end
    end
    f(object, name)
end

function update_func(new_func, old_func)
    assert("function" == type(new_func))
    assert("function" == type(old_func))

    -- Get upvalues of old function.
    local old_upvalue_map = {}
    local OldExistName = {}
    for i = 1, math.huge do
        local name, value = debug.getupvalue(old_func, i)
        if not name then break end
        old_upvalue_map[name] = value
        OldExistName[name] = true
        ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]","OldExistName "..name.." i :"..i..'-->'..tostring(value))
    end

    -- Update new upvalues with old.
    for i = 1, math.huge do
        local name, value = debug.getupvalue(new_func, i)
        if not name then break end
        --CS.UnityEngine.Debug.LogError('set up value: name:'..name..' typeof '.. type(value))
        if OldExistName[name] then
            local old_value = old_upvalue_map[name]
            if type(old_value) == "function" then
                --update_func(value,old_value)
                debug.setupvalue(new_func, i, old_value)
                ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]",name.." is function")
            else
                if old_value ~= value then
                    ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]","set "..name.."")
                    debug.setupvalue(new_func, i, old_value)
                end
            end

        else

             -- 对新添加的upvalue设置正确的环境表
            ResetENV(value,name)
        end
    end
end

function update_table(new_table, old_table, updated_tables)
    assert("table" == type(new_table))
    assert("table" == type(old_table))

    -- Compare 2 tables, and update old table.
    for key, value in pairs(new_table) do
        --CS.UnityEngine.Debug.LogError("update_table "..key..'-->'..tostring(value))
        local old_value = old_table[key]
        local type_value = type(value)
        if type_value == "function" then
            update_func(value, old_value)
            old_table[key] = value

        elseif type_value == "table" then
            if ( updated_tables[value] == nil ) then
                updated_tables[value] = true
                update_table(value, old_value,updated_tables)
            end
        end
    end

    ReleaseLogger.Log("[oook]", "[HotFix]", "[hotfix]","---- Update metatable")
    ---- Update metatable.
    local old_meta = debug.getmetatable(old_table)
    local new_meta = debug.getmetatable(new_table)
    if type(old_meta) == "table" and type(new_meta) == "table" then
        update_table(new_meta, old_meta,updated_tables)
    end
end
