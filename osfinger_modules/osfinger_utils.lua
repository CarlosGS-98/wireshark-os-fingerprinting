----------------------------------------
-- script-name: osfinger_utils.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023 - 2024, Carlos González Sanz
--
----------------------------------------

-- Metaplugin modules
--local lfs = require("lfs")
local xml2lua = require("xml2lua")

-- Our metaplugin's metatable
local osfinger_utils = {}

-- Metaplugin constants
CGS_OS_PROTO = "os-fingerprinting"
--- [END USER NOTE]: Change the line below this one if you want to use a different directory to locate this plugin and its modules ---
CGS_OS_WIRESHARK_PLUGIN_DIR = os.getenv("HOME") .. "/.local/lib/wireshark/plugins/"
CGS_OS_PLUGIN_MODULES_DIR = CGS_OS_WIRESHARK_PLUGIN_DIR .. "osfinger_modules/"

-- Satori's fingerprint files
OSFINGER_SATORI_DHCP = CGS_OS_PLUGIN_MODULES_DIR .. "dhcp.xml"
OSFINGER_SATORI_DNS = CGS_OS_PLUGIN_MODULES_DIR .. "dns.xml"
OSFINGER_SATORI_HTTP_SERVER = CGS_OS_PLUGIN_MODULES_DIR .. "web.xml"
OSFINGER_SATORI_HTTP_AGENT = CGS_OS_PLUGIN_MODULES_DIR .. "webuseragent.xml"
OSFINGER_SATORI_NTP = CGS_OS_PLUGIN_MODULES_DIR .. "ntp.xml"
OSFINGER_SATORI_SIP = CGS_OS_PLUGIN_MODULES_DIR .. "sip.xml"
OSFINGER_SATORI_SMB = CGS_OS_PLUGIN_MODULES_DIR .. "smb.xml"
OSFINGER_SATORI_SSH = CGS_OS_PLUGIN_MODULES_DIR .. "ssh.xml"
OSFINGER_SATORI_SSL = CGS_OS_PLUGIN_MODULES_DIR .. "ssl.xml"
OSFINGER_SATORI_TCP = CGS_OS_PLUGIN_MODULES_DIR .. "tcp.xml"

-- Global protocol stream tables

--. DHCP stream lookup table
osfinger_utils.dhcp_stream_table = {
    --[[
        Each entry in this table will have the following format:

        <stream_string_id> = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT},
            dhcp_os_data = {server = SERVER, user_agent = USER_AGENT}
        }, (...)
    ]]--
}

--- DNS stream lookup table
osfinger_utils.dns_stream_table = {
    --[[
        Each entry in this table will have the following format:

        <stream_string_id> = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT},
            dns_id = DNS_ID
        }, (...)
    ]]--
}

--. HTTP stream lookup table
osfinger_utils.http_stream_table = {
    --[[
        Each entry in this table will have the following format:

        <stream_string_id> = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT},
            http_os_data = {server = SERVER, user_agent = USER_AGENT}
        }, (...)
    ]]--
}

--. NTP stream lookup table
osfinger_utils.ntp_stream_table = {
    --[[
        Each entry in this table will have the following format:

        <stream_string_id> = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT},
            ntp_os_data = {server = SERVER, user_agent = USER_AGENT}
        }, (...)
    ]]--
}

-- SIP stream lookup table
osfinger_utils.sip_stream_table = {
    --[[
        Each entry in this table will have the following format:

        <stream_string_id> = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT}
            sip_os_data = {server = SERVER, (...)}
        }, (...)
    ]]--
}

--. SMB stream lookup table
osfinger_utils.smb_stream_table = {
    --[[
        Each entry in this table will have the following format:

        <stream_string_id> = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT},
            smb_os_data = {server = SERVER, user_agent = USER_AGENT}
        }, (...)
    ]]--
}

--. SSH stream lookup table
osfinger_utils.ssh_stream_table = {
    --[[
        Each entry in this table will have the following format:

        <stream_string_id> = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT},
            ssh_os_data = {server = SERVER, user_agent = USER_AGENT}
        }, (...)
    ]]--
}

--. TLS/SSL stream lookup table
osfinger_utils.ssl_stream_table = {
    --[[
        Each entry in this table will have the following format:

        <stream_string_id> = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT},
            ssl_os_data = {server = SERVER, user_agent = USER_AGENT}
        }, (...)
    ]]--
}

--. TCP stream lookup table
osfinger_utils.tcp_stream_table = {
    --[[
        Each entry in this table will have the following format:

        stream_string_id = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT}, -- ...Should I remove this?
            osfinger_data = {
                -- This is mainly to hold all the different values we store inside our protocol during a live/offline capture --
                stream_osfinger_name = CGS_OS_TCP_PROTO.os_name,
                stream_osfinger_class = CGS_OS_TCP_PROTO.os_class,
                stream_osfinger_devname = CGS_OS_TCP_PROTO.device_name,
                stream_osfinger_devtype = CGS_OS_TCP_PROTO.device_type,
                stream_osfinger_devvendor = CGS_OS_TCP_PROTO.device_vendor,
                (...)
            }
        }, (...)
    ]]--
}

-- Function that loads Satori's XML fingerprint files
-- and returns the contents of it:

function osfinger_utils.preloadXML(xml_file)
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

function osfinger_utils.signature_partition(finger_db, protocol_root, test_root)
    -- Traverse the entire DNS database to correctly
    -- store exact signatures matches and partial ones
    -- on separate tables, which will improve performance
    -- when performing database lookups:

    local finger_root = finger_db["fingerprints"]["fingerprint"]
    local exact_list, partial_list = {}, {}

    for _, record in ipairs(finger_root) do
        local exact_tests = {}
        local partial_tests = {}

        -- Manual filtering due to massive bugs
        -- when using LuaFun's API with our DB:

        if record[test_root]["test"] ~= nil then
            local record_flag = false
            for _, elem in ipairs(record[test_root]["test"]) do
                record_flag = true

                if elem["_attr"]["matchtype"] == "exact" then
                    table.insert(exact_tests, elem)
                else
                    table.insert(partial_tests, elem)
                end
            end

            if not record_flag then
                -- We have to use this as a fallback
                -- until we discover why our previous
                -- iterator gives up when the current
                -- record only contains a single test:

                if record[test_root]["test"]["_attr"]["matchtype"] == "exact" then
                    table.insert(exact_list, {info = record["_attr"], tests = record[test_root]["test"]})
                else
                    table.insert(partial_list, {info = record["_attr"], tests = record[test_root]["test"]})
                end
            else
                -- Add the current results to both tables
                -- if we extract any corresponding matches:

                if #exact_tests > 0 then
                    table.insert(exact_list, {info = record["_attr"], tests = exact_tests})
                end

                if #partial_tests > 0 then
                    table.insert(partial_list, {info = record["_attr"], tests = partial_tests})
                end
            end
        end
    end

    return exact_list, partial_list
end

return osfinger_utils
