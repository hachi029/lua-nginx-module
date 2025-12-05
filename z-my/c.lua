print(type(tonumber('1')))
local a = {{a='a1'},{a='a2'}}
print(#a)
for i,v in ipairs(a) do
	print(i,v.a)
end
print('---------str----------')
local str = '_test'
assert(string.sub(str, 2, 4) == 'tes')
assert(str:find('_') == 1)
assert(str:find('z') == nil)

assert(string.gsub(str,"t","b",1) == '_best')


print('---------and/or----------')

print('a' and false and 'd')
print(nil or 'b' and 'c')

print('---------test----------')
local b = {[1]='a',c = 'd'}
b['a'] = nil
for i,v in ipairs(b) do
	print(i,v)
end
print('---------test1----------')
for k,v in pairs(b) do
	print(k,v)
end

print('---------test2----------')
local d = {c='c_v',d='d_v'}
print(d.c)
print(d['c'])
--print(table.getn(d))
d['>'] = function( ... )
	print(...)
end
d['>']('xxxx')
print('---------test3----------')

local t = {}
t['a'] = 'a'

print(t['a'])
print(t['b'])
print(string.find('a', 'a'))
print(nil == false)
print(tostring(nil)=='nil')

print('---------test4----------')

local a = 123133333333333333
print(a)



