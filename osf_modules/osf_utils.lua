----------------------------------------
-- script-name: cgs_os_fingerutils.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023, Carlos González Sanz
--
----------------------------------------

-- Metaplugin modules
local lfs = require("lfs")
local xml2lua = require("xml2lua")

-- Our metaplugin's metatable
local osf_utils = {}

-- Metaplugin constants
CGS_OS_PROTO = "os-fingerprinting"
--- [END USER NOTE]: Change the line below this one if you want to use a different directory to locate Wireshark's plugins ---
CGS_OS_WIRESHARK_PLUGIN_DIR = os.getenv("HOME") .. "/.local/lib/wireshark/plugins/"
CGS_OS_PLUGIN_MODULES_DIR = CGS_OS_WIRESHARK_PLUGIN_DIR .. "osf_modules/"

-- Satori's fingerprint files
--OSF_SATORI_DHCP = CGS_OS_PLUGIN_MODULES_DIR .. "dhcp.xml"
--OSF_SATORI_DNS = CGS_OS_PLUGIN_MODULES_DIR .. "dns.xml"
--OSF_SATORI_ICMP = CGS_OS_PLUGIN_MODULES_DIR .. "icmp.xml"
--OSF_SATORI_SMB = CGS_OS_PLUGIN_MODULES_DIR .. "smb.xml"
--OSF_SATORI_SSL = CGS_OS_PLUGIN_MODULES_DIR .. "ssl.xml"
OSF_SATORI_TCP = CGS_OS_PLUGIN_MODULES_DIR .. "tcp.xml"
--OSF_SATORI_UDP = CGS_OS_PLUGIN_MODULES_DIR .. "udp.xml"

-- Function that loads Satori's XML fingerprint files
-- and returns the contents of it:

function osf_utils.preloadXML(xml_file)
    -- We first open our file so we can convert it
    -- to a string which we'll pass onto xml2lua
    -- to parse that XML string into a native Lua table:

    local file_handle = assert(io.open(xml_file, "r+"), "[ERROR]: Unable to load the corresponding fingerprints in XML")
    --[[
    if file_handle == nil then
        return nil
    end
    ]]--

    local file_contents = file_handle:read("*a")

    -- XML parser initialization
    local handler = require("xmlhandler.tree")
    local parser = xml2lua.parser(handler)
    parser:parse(tostring(file_contents))

    return handler.root
end

return osf_utils
