local jp = require('jsonpath')
local cjson = require('cjson')
local json = cjson.new()
local t = json.decode([[{
    "store": {
        "book": [{
                "category": "reference",
                "author": "Nigel Rees",
                "title": "Sayings of the Century",
                "price": 8.95
            }, {
                "category": "fiction",
                "author": "Evelyn Waugh",
                "title": "Sword of Honour",
                "price": 12.99
            }
        ],
        "bicycle": {
            "color": "red",
            "price": 19.95
        }
    },
     "id":12333311111111111111
}]])
print(tonumber(t['id']))
print(tonumber(t['id']) == tonumber(12333311111111111111))
print(jp.value(t, '$.id'))

local authors = jp.value(t, '$..book[1].title')
print(type(authors))
if type(authors) == 'table' then
    for k,v in pairs(authors) do
        print(k,v)
    end
else
    print(authors)
end