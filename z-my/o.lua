local _M={}

_M.version = '1.1'
function _M.new(config)
	local obj = setmetatable(
		{config = config, last_batch = 0,},
		{__index=_M, __mod='v'}
	)
	return obj
end

function _M:say(name)
	return self.config[name]
end

function _M.hi()
	return _M.version
end



return _M