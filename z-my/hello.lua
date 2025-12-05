People={}
function People.sayHi(self) 
	print("People sayHi:"..self.name)
end

function clone(tab) 
	copy = {}
        for k,v in pairs(tab) do
        	copy[k] = v
	end
	return copy;
end

People.new = function(name) 
	self = clone(People)
	self.name=name
	return self
end

local a = People.new("ZhangSan1")
a:sayHi()

a.name = "name1";
a.hi = function(self)
	print(self.name)
end
a.hi(a)


