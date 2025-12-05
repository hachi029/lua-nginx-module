local o = require('o')
local o_ins = o.new({a='value a'})

print(o_ins.config.a)
print(o_ins.version)

print(o_ins:say('a'))
print(o_ins.hi())


for k,v in pairs({{a='a1'},{b='b1'},{c='c1'}}) do
	print(k,v)
end
