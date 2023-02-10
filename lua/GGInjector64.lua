---
--- Created by yangtong02.
--- DateTime: 2023/2/9 13:40
--- GG lua 解析64位elf文件
---
---


sf	= string.format
function alert(caption, text)
	assert(caption ~= nil, "\n\n>> [alert]: error, caption was nil. <<\n\n")
	if text == nil then
		text = caption
		caption = "[Info]: Notice"
	end
	gg.alert(caption .. "\n\t- " .. text)
end
function rwmem(address, SizeOrBuffer)
	assert(type(address) ~= "string", "\n\n>> [rwmem]: error, address is string. Please check caller. <<\n\n")
	assert(address ~= nil, "\n\n>> [rwmem]: error, provided address is nil. <<\n\n")
	_rw = {}
	if type(SizeOrBuffer) == "number" then
		_ = ""
		for _ = 1, SizeOrBuffer do _rw[_] = {address = (address - 1) + _, flags = gg.TYPE_BYTE} end
		for v, __ in ipairs(gg.getValues(_rw)) do _ = _ .. string.format("%02X", __.value & 0xFF) end
		return _
	end
	Byte = {} SizeOrBuffer:gsub("..", function(x)
		Byte[#Byte + 1] = x _rw[#Byte] = {address = (address - 1) + #Byte, flags = gg.TYPE_BYTE, value = x .. "h"}
	end)
	gg.setValues(_rw)
end
function rdstr(address, strsz)
  assert(address ~= nil, "\n\n>> [rdstr]: error, provided address is nil. <<\n\n")
  if strsz == nil or type(strsz) ~= "number" then strsz = 128 end
  local str = ""
  for _ in rwmem(address, strsz):gmatch("..") do
    if _ == "00" then break end
      str = str .. string.char(tonumber(_, 16))
  end
  return str
end

---------------------------

function getLibraryBase(lib)
    print("search ".. lib)
    --print(gg.getRangesList(lib))
	for _, __ in pairs(gg.getRangesList(lib)) do
        print(sf("start 0x%x ~ 0x%x",__["start"], __["end"]))
		--if __["state"] == "Xa" or __["state"] == "Xs" then
        --    --print(sf("start 0x%x ~ 0x%x",__["start"], __["end"]))
        return __["start"], __["end"] end
	--end
	return nil
end
function getLibInformation(LibName)
	local LibBase = getLibraryBase(LibName)
    if LibBase == nil then
        print("can't find "..LibName)
    end
	if LibBase ~= nil then
		_ = gg.getValues({
			{address = LibBase, flags = gg.TYPE_DWORD },		-- Magic
			-- EI_PAD skipped --
			{address = LibBase + 0x12, flags = gg.TYPE_WORD },	-- Machine
			{address = LibBase + 0x20, flags = gg.TYPE_DWORD },	-- Program Header Table (PH) Offset
			{address = LibBase + 0x30, flags = gg.TYPE_DWORD },	-- Flags
			{address = LibBase + 0x36, flags = gg.TYPE_WORD },	-- Program Header Table (PH) Size Entry
			{address = LibBase + 0x38, flags = gg.TYPE_WORD },	-- Number Of Entries In Program Header Table (PH)
			})
		local Elf = { -- Elf Information Table Structure--
			Magic		= _[1].value,
			Machine 	= _[2].value,
			PHOffset 	= _[3].value,
			Flags 		= _[4].value,
			PHSize 		= _[5].value,
			PHNum		= _[6].value,
			pHdr		= {},
			Dyn			= {},
			Sym			= {},
			vAddress	= LibBase
		}
        print(sf("ELF info Magic %s ,PHOffset 0x%x PHNum 0x%x",Elf.Magic,Elf.PHOffset,Elf.PHSize))
		for _ = 1, Elf.PHNum do -- Parsing Program Header
			local _pHdr = LibBase + Elf.PHOffset + (_ * Elf.PHSize)
			local pHdr = gg.getValues({
				{ address = _pHdr, flags = gg.TYPE_DWORD }, 		-- p_type
				{ address = _pHdr + 8, flags = gg.TYPE_DWORD }, 	-- p_offset
				{ address = _pHdr + 0x10, flags = gg.TYPE_DWORD }, 	-- p_vaddr
				{ address = _pHdr + 0x18, flags = gg.TYPE_DWORD },	-- p_paddr
				{ address = _pHdr + 0x20, flags = gg.TYPE_DWORD },	-- p_filesz
				{ address = _pHdr + 0x28, flags = gg.TYPE_DWORD },	-- p_memsz
				{ address = _pHdr + 4, flags = gg.TYPE_DWORD },	-- p_flags
				--{ address = _pHdr + 0x30, flags = gg.TYPE_DWORD },	-- p_align
			})
			Elf.pHdr[_] = { -- All data in Program Header now in Elf.pHdr[Elf.PHNum]
				p_type		= pHdr[1].value,
				p_offset	= pHdr[2].value,
				p_vaddr		= pHdr[3].value,
				p_paddr		= pHdr[4].value,
				p_filesz	= pHdr[5].value,
				p_memsz		= pHdr[6].value,
				p_flags		= pHdr[7].value,
				--p_align		= pHdr[8].value
			}
            print(sf("pHdr type %d offset 0x%x  p_vaddr 0x%x ",pHdr[1].value,pHdr[2].value,pHdr[3].value))
		end
		for _ = 1, Elf.PHNum do  -- Parsing Dynamic Segment
			if Elf.pHdr[_].p_type == 2 then -- PT_DYNAMIC
				local DynCount = 0
				while true do
					local _Dyn = gg.getValues({
						{ address = LibBase + Elf.pHdr[_].p_vaddr + (DynCount * 8), flags = gg.TYPE_DWORD }, -- d_tag
						{ address = LibBase + Elf.pHdr[_].p_vaddr + 8 + (DynCount * 8), flags = gg.TYPE_DWORD } -- d_ptr / d_val
					})
					if _Dyn[1].value == 0 and _Dyn[2].value == 0 then break end -- End of dynamic segment
					DynCount = DynCount + 1 -- Keep growing !
					Elf.Dyn[DynCount] = { -- All data in Dynamic Segment now in Elf.Dyn[Section]
						d_tag = _Dyn[1].value,
						d_val = _Dyn[2].value,
						d_ptr = _Dyn[2].value
					}
				end
			end
		end
		return Elf
	end
	return nil
end

function getSymbolAddress(ElfData, symName)
	assert(ElfData ~= nil, "\n\n>> [getSymbolAddress]: error, provided ElfData is nil. <<\n\n")
	for _ = 1, #ElfData.Dyn do
			if tonumber(ElfData.Dyn[_].d_tag) == 4 then nChain = gg.getValues({{address = (ElfData.Dyn[_].d_ptr + 4) + ElfData.vAddress, flags = gg.TYPE_DWORD}})[1].value end
			if tonumber(ElfData.Dyn[_].d_tag) == 5 then strtab = ElfData.Dyn[_].d_ptr + ElfData.vAddress end
			if tonumber(ElfData.Dyn[_].d_tag) == 6 then symtab = ElfData.Dyn[_].d_ptr + ElfData.vAddress end
	end
    if nChain ~= nil then
        for _ = 1, nChain do
            local sym = symtab + (_ * 0x18)
            __ = gg.getValues({
                { address = sym, flags = gg.TYPE_DWORD },		-- st_name
                { address = sym + 0x4, flags = gg.TYPE_DWORD },	-- st_value
            })
            print(rdstr(strtab + __[1].value) .. ", offset:"..sf("0x%x",__[1].value))
            if rdstr(strtab + __[1].value) == symName then
                return ElfData.vAddress + __[2].value
            end
        end
    else
        print("nChain is nil")
    end

	return nil
end

function getLib(libName)
	gg.toast("Searching for '"..libName.."', This may take a while. Please wait...")
	local m_lib = getLibInformation(libName)
	if m_lib ~= nil then
		print(sf("[getLib]: %s Architecture: 0x%08X", libName, m_lib.Machine))
		if m_lib.Machine == 0xb7 then -- Arm 64-bits
            return m_lib
		end
		alert("[Error]: Unsupported Device !", "Currently, only Arm 64-bits device are supported.")
		os.exit()
		return nil
	end

	alert("[Error]: Missing dependencies !", "One of required shared library '" .. libName .. "', has left us in the dark.")
	os.exit()
	return nil
end
function getSymbol(ElfData, Symname)
    gg.toast("Searching for Symbol '"..Symname.."', This may take a while. Please wait...")
	local s_address = getSymbolAddress(ElfData, Symname)
	if s_address ~= nil then
		return s_address
	end

	alert("[Error]: Missing dependencies !", "One of required symbol '" .. Symname .. "', has been reported missing.")
	os.exit()
	return nil
end




local m_libdl		= getLib("libil2cpp.so")
local s_dlopen	= getSymbol(m_libdl, "il2cpp_assembly_get_image")
print("find dlopen "..s_dlopen)