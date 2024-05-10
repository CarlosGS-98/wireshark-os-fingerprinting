----------------------------------------
-- script-name: osfinger_menus.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023 - 2024, Carlos González Sanz
--
----------------------------------------

-- Metaplugin modules
--local lfs = require("lfs")
local cjson = require("cjson")

-- Our metaplugin's metatable
local osfinger_menus = {}

-- GUI Menu Functions
function osmenu_display_stream_tables()
    if not gui_enabled() then return end

    -- create new text window and initialize its text
    local win = TextWindow.new("OS Fingerprinting Stream Tables")

    -- Parse all the stream tables we have
    -- (this works only with TCP for the moment for testing purposes):

    local tcp_table_json = cjson.encode(cgs_tcp_stream_table)

    win:set(tcp_table_json)

    -- add buttons to clear text window and to enable editing
    win:add_button("Clear", function() win:clear() end)
    win:add_button("Enable edit", function() win:set_editable(true) end)

    -- add button to change text to uppercase
    win:add_button("Uppercase", function()
            local text = win:get_text()
            if text ~= "" then
                    win:set(string.upper(text))
            end
    end)

    -- print "closing" to stdout when the user closes the text window
    win:set_atclose(function() print("closing") end)
end

-- Registers all relevant menus so we can
-- use them inside Wireshark in GUI mode:

-- Stream Table GUI Functions
register_menu("OS Fingerprinting/Display Stream Tables", osmenu_display_stream_tables, MENU_TOOLS_UNSORTED)
