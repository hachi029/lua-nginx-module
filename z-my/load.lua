local fun = function (arg)
	print(arg)
	return 'fun return value'
end
local newfenv = {b='hi'}
local b = load('return a("c1")', nil, nil, {a = fun})
print(b())