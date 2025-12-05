function a() 
	return (false and true)
end
if not a() then
	print('true')
end
local c = nil
print(type(c))

local a = string.find("mskjkangjunfei", "mskj")
print(a)
local c = {}
c[1]='xxx'
print(c[1])
c[1]=nil
print(c[1])

print(string.gsub("ada?code=a", "?code=a", ""))
print(string.gsub("ada?a=c&code=a", "&code=a", ""))
print(string.match('JSESSIONID=BNNDD-asd_asd; Path=/; HttpOnly', '.*JSESSIONID=([%w_-]+);.*'))

-- local a = function(cc) 
-- 	return string.char(tonumber(cc, 16))
-- end

-- print("aaa":gsub('..', a))


local function hex2str(hex)
	local str, n = hex:gsub("..", function (w) return string.char(tonumber(w, 16)) end)
	return str
end

local function str2hex(str)
	local hex = ""
	for i=0, string.len(str)-1 do
		local k = i+1
		local b = string.byte(str, k, k)
		hex = hex..string.format("%02x", b)
	end

	return hex
end


local function str2hex1(str)
	
	return (str:gsub('.', function(c)
			return string.format("%02x", string.byte(c))
		end))
end

print(str2hex1('A123'))
print(str2hex1('中国人123'))
print(hex2str('41313233'))
print(hex2str('e4b8ade59bbde4baba313233'))

local function RandomVariable(length)
	local res = ""
	for i = 1, length do
		res = res .. string.char(math.random(65, 90))
	end
	return res
end

print(RandomVariable(32))