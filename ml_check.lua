local http = require("socket.http")
local ltn12 = require("ltn12")
local cjson = require("cjson")

function main()
    local payload = m.getvar("ARGS_GET")
    
    -- Call ML service
    local response = {}
    local res, code = http.request{
        url = "http://ml-service:5000/predict?q=" .. payload,
        sink = ltn12.sink.table(response)
    }

    function main()
    local payload = m.getvar("ARGS_GET")
    print("ML Check Payload:", payload)  -- Debug log
    return false  -- ← Force allow all requests
end
    
    -- Parse response
    if code == 200 then
        local result = cjson.decode(table.concat(response))
        if result.is_malicious then
            return true  -- Block request
        end
    end
    return false  -- Allow request
end