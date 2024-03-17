----------------------------------------
-- script-name: cgs_dhcp_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023 - 2024, Carlos González Sanz
--
----------------------------------------

local osf = require("osf_utils")
--local fun = require("fun")
local inspect = require("inspect")
local md5 = require("md5")

local osf_http_dissector = {}

-- Plugin constants/global variables
CGS_OS_HTTP_PROTO = CGS_OS_PROTO .. "-http"

-- Fingerprinting protocol for TCP
local cgs_http_proto = Proto(CGS_OS_HTTP_PROTO, "OS Fingerprinting - HTTP")

--- Fields for this HTTP postdissector ---
-- (WIP) --

--- Extra functions for this DHCP postdissector ---
-- (WIP) --

function cgs_http_proto.dissector(buffer, pinfo, tree)
    -- (WIP) --
end