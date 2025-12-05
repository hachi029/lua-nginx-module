require "hello"
print(package.path)
local a = {name="LiSi"}
local b = {}
local index = function(table, key)
	print("__index:"..key..":"..table['name'])
	return 1
end
local add = function(table, v) 
	print("__add"..(table['age']+v))
	table['age'] = table['age']+v
	return table
end
local newindex = function(table, key, value)
	print("__newindex:"..key..':'..value)
end

local call = function(self, index) 
	print("in call")
	return "call return"..index
end

setmetatable(a,b)
b.__index=index
b.__add = add
b.__newindex=newindex
b.__call = call
print(a.age)
print((a+10)['age'])
print(a("axx"))
print(nil)
print 'a'
print(type(1))
assert(type('1') == 'string', 'not a string')
error(('Not implemented: %s'):format("a"))


