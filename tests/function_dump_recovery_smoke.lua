local state = { salt = tonumber("17") }

local function handler(value)
    state.salt += 1
    return value + state.salt
end

return {
    d = handler,
}
