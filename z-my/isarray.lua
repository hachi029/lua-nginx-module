local isarray = require "table.isarray"

print(isarray{"a", true, 3.14})  -- true
print(isarray{dog = 3})  -- false
print(isarray{})  -- true
local t = {}
t[2] = 'v2'
t[3] = 'v3'
t[5] = 'v5'
print(isarray(t))  -- true

for i,  v in ipairs(t) do   -- null
    print(i,v)
end