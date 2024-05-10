----------------------------------------
-- script-name: cgs_http_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023 - 2024, Carlos González Sanz
--
----------------------------------------

local osfinger = require("osfinger_utils")
--local fun = require("fun")
local inspect = require("inspect")
local md5 = require("md5")

local osfinger_http_dissector = {}

-- Plugin constants/global variables
CGS_OS_HTTP_PROTO = CGS_OS_PROTO .. "-http"
HTTP_NO_NAME = "NONE"

-- Fingerprinting protocol for TCP
local cgs_http_proto = Proto(CGS_OS_HTTP_PROTO, "OS Fingerprinting - HTTP")

--- Fields for this HTTP postdissector ---
local osfinger_http_check = Field.new("http")
local osfinger_http_web_server = Field.new("http.server")
local osfinger_http_user_agent = Field.new("http.user_agent")
-- (WIP) --

-- Fields for the HTTP dissection tree
local osfinger_http_full_name_F = ProtoField.string(CGS_OS_HTTP_PROTO .. ".full_name", "Device/OS Full Name", "Can include version info about the given OS if it's one")  
local osfinger_http_os_name_F = ProtoField.string(CGS_OS_HTTP_PROTO .. ".os_name", "OS Name")                                                      -- "name" (instead of "os_name", since it's empty most of the time)
local osfinger_http_os_class_F = ProtoField.string(CGS_OS_HTTP_PROTO .. ".os_class", "OS Class", "The OS family that this system belongs to")      -- "os_class"
local osfinger_http_os_vendor_F = ProtoField.string(CGS_OS_HTTP_PROTO .. ".os_vendor", "OS Vendor", "The OS vendor/distributor of this system")    -- "os_vendot"                   -- "device_name"
local osfinger_http_device_type_F = ProtoField.string(CGS_OS_HTTP_PROTO .. ".device_type", "Device Type", "Device type/class")                     -- "device_type"
local osfinger_http_device_vendor_F = ProtoField.string(CGS_OS_HTTP_PROTO .. ".device_vendor", "Device Vendor")
local osfinger_http_server_F = ProtoField.string(CGS_OS_HTTP_PROTO .. ".web_server", "Web Server", "The server this packet was sent from")
local osfinger_http_agent_F = ProtoField.string(CGS_OS_HTTP_PROTO .. ".user_agent", "User Agent", "The agent that made the current request")

-- Add fields to the pseudo-protocol
cgs_http_proto.fields = {
    osfinger_http_full_name_F,
    osfinger_http_os_name_F,
    osfinger_http_os_class_F,
    osfinger_http_os_vendor_F,
    osfinger_http_device_type_F,
    osfinger_http_device_vendor_F,
    osfinger_http_server_F,
    osfinger_http_agent_F
}

-- Base TCP/IP adresses and ports (in part to build a lookup table)
local osfinger_ip_src = Field.new("ip.src")
local osfinger_ip_dst = Field.new("ip.dst")
local osfinger_tcp_src = Field.new("tcp.srcport")
local osfinger_tcp_dst = Field.new("tcp.dstport")

-- Extra field for storing an HTTP stream lookup table
local cgs_http_stream_table = {
    --[[
        Each entry in this table will have the following format:

        <stream_string_id> = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT},
            http_os_data = {server = SERVER, user_agent = USER_AGENT}
        }, (...)
    ]]--
}

-- Preload Satori's HTTP signatures
local osfinger_http_server_xml = osfinger.preloadXML(OSFINGER_SATORI_HTTP_SERVER)
local osfinger_http_agent_xml = osfinger.preloadXML(OSFINGER_SATORI_HTTP_AGENT)

--- Extra functions for this HTTP postdissector ---
-- (WIP) --
local function osfinger_http_signature_partition(finger_db, protocol_root, test_root)
    -- Traverse the entire DNS database to correctly
    -- store exact signatures matches and partial ones
    -- on separate tables, which will improve performance
    -- when performing database lookups:

    local finger_root = finger_db[protocol_root]["fingerprints"]["fingerprint"]
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

local osfinger_http_server_exact_list, osfinger_http_server_partial_list = osfinger_http_signature_partition(osfinger_http_server_xml, "WEBSERVER", "webserver_tests")
local osfinger_http_agent_exact_list, osfinger_http_agent_partial_list = osfinger_http_signature_partition(osfinger_http_agent_xml, "WEBUSERAGENT", "webuseragent_tests")

function osfinger_http_dissector.osfinger_http_webserver_match(cur_packet_data)
    local http_webserver_names = {}

    -- Because the signature info Satori provides us for HTTP
    -- only contains web server names in "web.xml",
    -- we must search both lists in order to find a given web server match.
    --
    -- If we end up traversing the entire exact list
    -- without finding any match, then we should look up
    -- the partial list so as to try to find a match,
    -- which will have percentage data based on the weight
    -- of the current match as well as the number of records
    -- we retrieve from that list.

    local total_record_weight = 0
    local total_matches = 0
    local record_flag = false

    print("Wir suchen gerade innerhalb beider Web-Server Listen...")

    --- HTTP Web Server ---

    --- HTTP User Agent ---
    -- HTTP exact list traversal
    for index, elem in ipairs(osfinger_http_server_exact_list) do
        print("Analizing exact user matches... (" .. tostring(index) .. ")")
        
        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true

            if tostring(test_record["_attr"]["webserver"]) == tostring(cur_packet_data["web_server"]) then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(http_webserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                return {http_webserver_names[1], total_record_weight, 1}   -- Since it's an exact match
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if tostring(elem["tests"]["_attr"]["webserver"]) == tostring(cur_packet_data["web_server"]) then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(http_webserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                return {http_webserver_names[1], total_record_weight, 1}   -- Since it's an exact match
            end
        end
    end

    print("Responses (After exact matches (Web Server)) = " .. tostring(inspect(http_webserver_names)))

    -- DNS partial list traversal (if we need to)
    for _, elem in ipairs(osfinger_http_server_partial_list) do
        --print("Record flag = " .. tostring(record_flag))
        --print("Current partial element = " .. tostring(inspect(elem)))
        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true
            print(test_record["_attr"]["webserver"])
            print(tostring(test_record["_attr"]["webserver"]) .. " (VS) " .. tostring(cur_packet_data["web_server"]))
            print(tostring(string.match(tostring(test_record["_attr"]["webserver"]), tostring(cur_packet_data["web_server"])) ~= nil))

            if string.match(tostring(test_record["_attr"]["webserver"]), tostring(cur_packet_data["web_server"])) ~= nil then
            --if tostring(test_record["_attr"]["webserver"]) == cur_packet_data["user_agent"] then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(http_webserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(test_record["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end

        --print("Haben wir das Vorherige überlebt?")
        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if string.match(tostring(elem["tests"]["_attr"]["webserver"]), cur_packet_data["web_server"]) ~= nil then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(http_webserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end
    end

    print("Responses (After partial matches (Web Server)) = " .. tostring(inspect(http_webserver_names)))

    if total_record_weight > 0 then
        table.sort(http_webserver_names, function(r1, r2)
            return r1["weight"] > r2["weight"]
        end)

        print(inspect(http_webserver_names))

        return {http_webserver_names[1], total_record_weight, total_matches}
    else
        return nil
    end
end

function osfinger_http_dissector.osfinger_http_useragent_match(cur_packet_data)
    local http_useragent_names = {}

    -- Because the signature info Satori provides us for HTTP
    -- only contains user agent names in "webuseragent.xml",
    -- we must search both lists in order to find a given user agent match.
    --
    -- If we end up traversing the entire exact list
    -- without finding any match, then we should look up
    -- the partial list so as to try to find a match,
    -- which will have percentage data based on the weight
    -- of the current match as well as the number of records
    -- we retrieve from that list.


    local total_record_weight = 0
    local total_matches = 0
    local record_flag = false

    --- HTTP Web Server ---
    print("Wir suchen gerade innerhalb beider Benutzeragentenlisten...")

    --- HTTP User Agent ---
    -- HTTP exact list traversal
    for _, elem in ipairs(osfinger_http_agent_exact_list) do
        
        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true

            if tostring(test_record["_attr"]["webuseragent"]) == tostring(cur_packet_data["user_agent"]) then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(http_useragent_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                return {http_useragent_names[1], total_record_weight, 1}   -- Since it's an exact match
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if tostring(elem["tests"]["_attr"]["webuseragent"]) == tostring(cur_packet_data["user_agent"]) then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(http_useragent_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                return {http_useragent_names[1], total_record_weight, 1}   -- Since it's an exact match
            end
        end
    end

    print("Responses (After exact matches (User Agent)) = " .. tostring(inspect(http_useragent_names)))

    -- DNS partial list traversal (if we need to)
    for _, elem in ipairs(osfinger_http_agent_partial_list) do
        --print("Record flag = " .. tostring(record_flag))
        --print("Current partial element = " .. tostring(inspect(elem)))
        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true
            print(test_record["_attr"]["webuseragent"])
            print(tostring(test_record["_attr"]["webuseragent"]) .. " (VS) " .. tostring(cur_packet_data["user_agent"]))
            print(tostring(string.match(tostring(test_record["_attr"]["webuseragent"]), tostring(cur_packet_data["user_agent"])) ~= nil))

            if string.match(tostring(test_record["_attr"]["webuseragent"]), tostring(cur_packet_data["user_agent"])) ~= nil then
            --if tostring(test_record["_attr"]["webuseragent"]) == cur_packet_data["user_agent"] then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(http_useragent_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(test_record["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end

        --print("Haben wir das Vorherige überlebt?")
        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if string.match(tostring(elem["tests"]["_attr"]["webuseragent"]), cur_packet_data["user_agent"]) ~= nil then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(http_useragent_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end
    end

    print("Responses (After partial matches (User Agent)) = " .. tostring(inspect(http_useragent_names)))

    if total_record_weight > 0 then
        table.sort(http_useragent_names, function(r1, r2)
            return r1["weight"] > r2["weight"]
        end)

        print(inspect(http_useragent_names))

        return {http_useragent_names[1], total_record_weight, total_matches}
    else
        return nil
    end
end

function cgs_http_proto.dissector(buffer, pinfo, tree)
    -- (WIP) --

    -- HTTP Fields
    local http_check = osfinger_http_check()
    local http_server = osfinger_http_web_server()
    local http_agent = osfinger_http_user_agent()

    -- TCP/IP Fields
    local ip_src = osfinger_ip_src()
    local ip_dst = osfinger_ip_dst()
    local tcp_src = osfinger_tcp_src()
    local tcp_dst = osfinger_tcp_dst()

    if http_check ~= nil and ip_src ~= nil and ip_dst ~= nil then
        local http_tree = tree:add(cgs_http_proto, "OS Fingerprinting through HTTP")
        local http_os_data = {}

        -- print("Web Server = " .. tostring(http_server.value or nil))
        -- print("User Agent = " .. tostring(http_agent.value or nil))
        local http_webserver_data = nil
        local http_useragent_data = nil

        if (http_server ~= nil and http_server.value ~= nil) or (http_agent ~= nil and http_agent.value ~= nil) then
            -- We first calculate the stream ID based on the current addresses and ports
            local cur_stream_id = md5.sumhexa(tostring(ip_src) .. tostring(ip_dst) .. tostring(tcp_src) .. tostring(tcp_dst)) -- For consistency
            local temp_http_sig = {}

            if cgs_http_stream_table[cur_stream_id] == nil then
                -- Build a new entry in the stream table
                -- with the current address and port info:

                cgs_http_stream_table[cur_stream_id] = {}
                print("New HTTP stream ID detected: " .. cur_stream_id)
                print("Address pair: [" .. tostring(ip_src) .. ":" .. tostring(tcp_src) .. ", " .. tostring(ip_dst) .. ":" .. tostring(tcp_dst) .. "]")

                -- Fill the current entry in the HTTP stream table
                cgs_http_stream_table[cur_stream_id]["ip_pair"] = {
                    src_ip = tostring(ip_src),
                    dst_ip = tostring(ip_dst)
                }

                cgs_http_stream_table[cur_stream_id]["port_pair"] = {
                    src_port = tostring(tcp_src),
                    dst_port = tostring(tcp_dst)
                }

                print(inspect(cgs_http_stream_table[cur_stream_id]))

                -- After that, the next step is to build
                -- our ad-hoc and compare it
                -- against the entries we have inside Satori's
                -- fingerprint database:

                print(tostring(http_server ~= nil))
                print(tostring(http_agent ~= nil))

                if http_server ~= nil then
                    temp_http_sig["web_server"] = http_server.value
                end

                if http_agent ~= nil then
                    temp_http_sig["user_agent"] = http_agent.value
                end

                print(inspect(temp_http_sig) .. "\n")

                -- Check whether we have a web server match
                if temp_http_sig["web_server"] ~= nil then
                    http_webserver_data = osfinger_http_dissector.osfinger_http_webserver_match(temp_http_sig)
                    print("Do we have web server data?: " .. tostring(http_webserver_data ~= nil))
                    if http_webserver_data ~= nil then
                        print("Webserver Data = " .. tostring(inspect(http_webserver_data[1])) .. "\n")
                    end
                end

                -- Check whether we have a web user agent match
                if temp_http_sig["user_agent"] ~= nil then
                    http_useragent_data = osfinger_http_dissector.osfinger_http_useragent_match(temp_http_sig)
                    print("Do we have user agent data?: " .. tostring(http_useragent_data ~= nil))
                    if http_useragent_data ~= nil then
                        print("User Agent Data = " .. tostring(inspect(http_useragent_data[1])) .. "\n")
                    end
                end
            end
        end

        -- (WIP)
        -- After all those checks, we finally display
        -- all the relevant info from our current packet:
        local packet_full_name = "Unknown"
        local packet_os_name = "Unknown"
        local packet_os_class = "Unknown"
        local packet_os_vendor = "Unknown"
        local packet_device_type = "Unknown"
        local packet_device_vendor = "Unknown"
        local packet_web_server_name = "Unknown"
        local packet_user_agent_name = "Unknown"

        --print("Current OS Data = " .. inspect(tcp_os_data))

        if (http_useragent_data ~= nil and tostring(http_useragent_data[1]["name"]) ~= "") then
            packet_full_name = http_useragent_data[1]["name"]
        end

        if (http_webserver_data ~= nil and tostring(http_webserver_data[1]["name"]) ~= "") then
            packet_full_name = http_webserver_data[1]["name"]
        end


        if (http_useragent_data ~= nil and tostring(http_useragent_data[1]["os_name"]) ~= "") then
            packet_full_name = http_useragent_data[1]["os_name"]
        end

        if (http_webserver_data ~= nil and tostring(http_webserver_data[1]["os_name"]) ~= "") then
            packet_os_name = http_webserver_data[1]["os_name"]
        end


        if (http_useragent_data ~= nil and tostring(http_useragent_data[1]["os_class"]) ~= "") then
            packet_full_name = http_useragent_data[1]["os_class"]
        end

        if (http_webserver_data ~= nil and tostring(http_webserver_data[1]["os_class"]) ~= "") then
            packet_os_class = http_webserver_data[1]["os_class"]
        end


        if (http_useragent_data ~= nil and tostring(http_useragent_data[1]["os_vendor"]) ~= "") then
            packet_full_name = http_useragent_data[1]["os_vendor"]
        end

        if (http_webserver_data ~= nil and tostring(http_webserver_data[1]["os_vendor"]) ~= "") then
            packet_os_vendor = http_webserver_data[1]["os_vendor"]
        end


        if (http_useragent_data ~= nil and tostring(http_useragent_data[1]["device_type"]) ~= "") then
            packet_full_name = http_useragent_data[1]["device_type"]
        end

        if (http_webserver_data ~= nil and tostring(http_webserver_data[1]["device_type"]) ~= "") then
            packet_device_type = http_webserver_data[1]["device_type"]
        end


        if (http_useragent_data ~= nil and tostring(http_useragent_data[1]["device_vendor"]) ~= "") then
            packet_full_name = http_useragent_data[1]["device_vendor"]
        end

        if (http_webserver_data ~= nil and tostring(http_webserver_data[1]["device_vendor"]) ~= "") then
            packet_device_vendor = http_webserver_data[1]["device_vendor"]
        end


        if (http_webserver_data ~= nil and tostring(http_webserver_data[1]["name"]) ~= "") then
            packet_web_server_name = http_webserver_data[1]["name"]
        end


        if (http_useragent_data ~= nil and tostring(http_useragent_data[1]["webuseragent"]) ~= "") then
            packet_user_agent_name = http_useragent_data[1]["webuseragent"]
        end

        print("Current HTTP Info: (" .. packet_full_name .. " (" .. packet_os_name .. "), " .. packet_os_class .. "; " .. packet_os_vendor .. "; " .. packet_device_type .. " (by " .. packet_device_vendor .. ")); " .. packet_web_server_name .. "; " .. packet_user_agent_name)

        http_tree:add(osfinger_http_full_name_F, packet_full_name)
        http_tree:add(osfinger_http_os_name_F, packet_os_name)
        http_tree:add(osfinger_http_os_class_F, packet_os_class)
        http_tree:add(osfinger_http_os_vendor_F, packet_os_vendor)
        http_tree:add(osfinger_http_device_type_F, packet_device_type)
        http_tree:add(osfinger_http_device_vendor_F, packet_device_vendor)
        http_tree:add(osfinger_http_server_F, packet_web_server_name)
        http_tree:add(osfinger_http_agent_F, packet_user_agent_name)
    end
end

register_postdissector(cgs_http_proto)

-- local udp_port_table = DissectorTable.get("udp.port")
-- local dns_port_table = udp_port_table:get_dissector(53)
-- dns_port_table:add("-", cgs_dns_proto)

return osfinger_http_dissector
