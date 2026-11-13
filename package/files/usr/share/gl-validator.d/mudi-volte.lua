-- Parameter checks of the GL admin panel's RPC core (/usr/lib/lua/oui/rpc.lua)
-- for the mudi-volte module. Without this file every string parameter has to
-- match '^[%w%.%s%-_:#/]-$': '*' and '+' in the call settings and most
-- passwords would be refused with "Invalid params" before the module sees
-- them. The module checks every value itself (/usr/lib/oui-httpd/rpc/mudi-volte);
-- these patterns only let through the characters the values may contain.
-- Methods not listed here keep the core's default check.

local function printable(v)
    return type(v) == "string" and #v <= 256 and not v:find("%c")
end

return {
    set_config = {
        incoming = "^%a*$",
        allow = "^[%+%d ]*$", -- each number of the list
        dial = "^[%*%+%d ]*$",
        country = "^%d*$"
    },
    set_push = {
        login = "^[%w%._%+%-@]*$",
        password = printable
    }
}
