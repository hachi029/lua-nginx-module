local a = nil
if a  or a == false then
	print('true')
end

local b = load("return ".."{id = 1, num = 666}")()
print(type(load))
print(type(b))
print(b['id'])
print(b['num'])

newfenv = {}
setfenv(1, newfenv)
print(1)        -- attempt to call global `print' (a nil value)