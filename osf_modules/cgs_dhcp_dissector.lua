----------------------------------------
-- script-name: cgs_dhcp_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023, Carlos González Sanz
--
----------------------------------------

local osf = require("osf_utils")
local fun = require("fun")
local inspect = require("inspect")
--local md5 = require("md5")

local osf_dhcp_dissector = {}

-- Plugin constants/global variables
CGS_OS_DHCP_PROTO = CGS_OS_PROTO .. "-dhcp"

-- Fingerprinting protocol for TCP
local cgs_dhcp_proto = Proto(CGS_OS_DHCP_PROTO, "OS Fingerprinting - DHCP")

--- Fields for this DHCP postdissector ---
-- (WIP) --

--- Extra functions for this DHCP postdissector ---
-- (WIP) --

function cgs_dhcp_proto.dissector(buffer, pinfo, tree)
    -- (WIP) --
end