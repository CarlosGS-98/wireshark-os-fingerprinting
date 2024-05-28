----------------------------------------
-- script-name: cgs_sip_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023 - 2024, Carlos González Sanz
--
----------------------------------------

local osfinger = require("osfinger_utils")
local inspect = require("inspect")
local md5 = require("md5")

local osfinger_sip_dissector = {
    sip_stream_table = {}
}

-- Plugin constants/global variables
CGS_OS_SIP_PROTO = CGS_OS_PROTO .. "-sip"
SIP_NO_NAME = "NONE"

-- Fingerprinting protocol for SIP
local cgs_sip_proto = Proto(CGS_OS_SIP_PROTO, "OS Fingerprinting - SIP")

--- Fields for this SIP postdissector ---
local osfinger_sip_server = Field.new("sip.Server")

-- Fields for the SIP dissection tree
local osfinger_sip_full_name_F = ProtoField.string(CGS_OS_SIP_PROTO .. ".full_name", "Device/OS Full Name", "Can include version info about the given OS if it's one")  
local osfinger_sip_os_name_F = ProtoField.string(CGS_OS_SIP_PROTO .. ".os_name", "OS Name")                                                      -- "name" (instead of "os_name", since it's empty most of the time)
local osfinger_sip_os_class_F = ProtoField.string(CGS_OS_SIP_PROTO .. ".os_class", "OS Class", "The OS family that this system belongs to")      -- "os_class"
local osfinger_sip_os_vendor_F = ProtoField.string(CGS_OS_SIP_PROTO .. ".os_vendor", "OS Vendor", "The OS vendor/distributor of this system")    -- "os_vendot"                   -- "device_name"
local osfinger_sip_device_type_F = ProtoField.string(CGS_OS_SIP_PROTO .. ".device_type", "Device Type", "Device type/class")                     -- "device_type"
local osfinger_sip_device_vendor_F = ProtoField.string(CGS_OS_SIP_PROTO .. ".device_vendor", "Device Vendor")

-- Add fields to the pseudo-protocol
cgs_sip_proto.fields = {osfinger_sip_full_name_F, osfinger_sip_os_name_F, osfinger_sip_os_class_F, osfinger_sip_os_vendor_F, osfinger_sip_device_type_F, osfinger_sip_device_vendor_F}

-- Base TCP/IP adresses and ports (in part to build a lookup table)
local osfinger_ip_src = Field.new("ip.src")
local osfinger_ip_dst = Field.new("ip.dst")
local osfinger_tcp_src = Field.new("tcp.srcport")
local osfinger_tcp_dst = Field.new("tcp.dstport")
local osfinger_udp_src = Field.new("udp.srcport")
local osfinger_udp_dst = Field.new("udp.dstport")

-- Preload Satori's SIP signatures
local osfinger_sip_xml = osfinger.preloadXML(OSFINGER_SATORI_SIP)["SIPSERVER"]
local osfinger_sip_exact_list, osfinger_sip_partial_list = osfinger.signature_partition(osfinger_sip_xml, "SIPSERVER", "sipserver_tests")

--- Extra functions for this SIP postdissector ---
function osfinger_sip_dissector.osfinger_sip_match(cur_packet_data)
    local sip_sipserver_names = {}

    -- Because the signature info Satori provides us for SIP
    -- only contains server names in "sip.xml",
    -- we must search both lists in order to find a given SIP server match.
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

    --- SIP Server ---
    -- SIP exact list traversal
    for index, elem in ipairs(osfinger_sip_exact_list) do
        record_flag = false
        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true

            if tostring(test_record["_attr"]["sipserver"]) == tostring(cur_packet_data["sip_server"]) then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(sip_sipserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                return {sip_sipserver_names[1], total_record_weight, 1}   -- Since it's an exact match
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if tostring(elem["tests"]["_attr"]["sipserver"]) == tostring(cur_packet_data["sip_server"]) then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(sip_sipserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                return {sip_sipserver_names[1], total_record_weight, 1}   -- Since it's an exact match
            end
        end
    end

    -- SIP partial list traversal (if we need to)
    for _, elem in ipairs(osfinger_sip_partial_list) do
        record_flag = false

        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true

            if string.match(tostring(cur_packet_data["sip_server"]), tostring(test_record["_attr"]["sipserver"])) ~= nil then
            --if tostring(test_record["_attr"]["sipserver"]) == cur_packet_data["user_agent"] then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(sip_sipserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(test_record["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if string.match(cur_packet_data["sip_server"], tostring(elem["tests"]["_attr"]["sipserver"])) ~= nil then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(sip_sipserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end
    end

    if total_record_weight > 0 then
        -- table.sort(sip_sipserver_names, function(r1, r2)
        --     return r1["weight"] > r2["weight"]
        -- end)
        --return {sip_sipserver_names[1], total_record_weight, total_matches}
        return sip_sipserver_names[1]
    else
        return nil
    end
end

function cgs_sip_proto.dissector(buffer, pinfo, tree)
    -- Looking at Wireshark's documentation,
    -- it seems that we should only deal
    -- with TCP/UDP packets whose origin ports
    -- are 5061 or 5060, respectively
    -- (at least by default).

    local ip_src = osfinger_ip_src()
    local ip_dst = osfinger_ip_dst()
    local tcp_src = osfinger_tcp_src()
    local tcp_dst = osfinger_tcp_dst()
    local udp_src = osfinger_udp_src()
    local udp_dst = osfinger_udp_dst()

    local sip_server = osfinger_sip_server()
    local visited_packet = pinfo.visited

    -- Check which transport layer protocol was used
    local cur_src_port = udp_src or tcp_src
    local cur_dst_port = udp_dst or tcp_dst

    if ip_src ~= nil
    and ip_dst ~= nil
    and cur_src_port ~= nil
    and cur_dst_port ~= nil
    and sip_server ~= nil
    and (cur_src_port.value == 5060 or cur_dst_port.value == 5061)
    and (cur_dst_port.value == 5060 or cur_dst_port.value == 5061) then
        
        local sip_tree = tree:add(cgs_sip_proto, "OS Fingerprinting through SIP")
        local sip_os_data = {}

        -- We first calculate the stream ID based on the current addresses and ports
        local cur_stream_id = md5.sumhexa(tostring(ip_src) .. tostring(ip_dst) .. tostring(cur_src_port) .. tostring(cur_dst_port)) -- For consistency
        local temp_sip_sig = {}

        if osfinger.sip_stream_table[cur_stream_id] == nil then
            -- Build a new entry in the stream table
            -- with the current address and port info:

            osfinger.sip_stream_table[cur_stream_id] = {}

            -- Fill the current entry in the DNS stream table
            osfinger.sip_stream_table[cur_stream_id]["ip_pair"] = {
                src_ip = tostring(ip_src),
                dst_ip = tostring(ip_dst)
            }

            osfinger.sip_stream_table[cur_stream_id]["port_pair"] = {
                src_port = tostring(cur_src_port),
                dst_port = tostring(cur_dst_port)
            }

            -- After that, the next step is to build
            -- our signature (in p0f format) and compare it
            -- against the entries we have inside Satori's
            -- fingerprint database:

            temp_sip_sig = {
                sip_server = tostring(sip_server.value) or SIP_NO_NAME,
                -- Other options will be added later if they exist in the current packet
            }

            -- Let's check what we got back
            sip_os_data = osfinger_sip_dissector.osfinger_sip_match(temp_sip_sig)

            if sip_os_data ~= nil then
                -- Store the result in the current stream record
                osfinger.sip_stream_table[cur_stream_id]["os_data"] = sip_os_data
            end
            -- (...)
        else
            -- If we get here, we just assume that
            -- this packet belongs to a previous stream:

            --- [TODO]: Fetch SIP signature info for the current packet ---
            if osfinger.sip_stream_table[cur_stream_id]["os_data"] ~= nil then
                sip_os_data = osfinger.sip_stream_table[cur_stream_id]["os_data"]
            end
        end

        -- After all those checks, we finally display
        -- all the relevant info from our current packet:

        local packet_full_name = "Unknown"
        local packet_os_name = "Unknown"
        local packet_os_class = "Unknown"
        local packet_os_vendor = "Unknown"
        local packet_device_type = "Unknown"
        local packet_device_vendor = "Unknown"

        if (sip_os_data ~= nil and (sip_os_data["name"]) ~= "") then
            packet_full_name = sip_os_data["name"]
        end

        if (sip_os_data ~= nil and (sip_os_data["os_name"]) ~= "") then
            packet_os_name = sip_os_data["os_name"]
        end

        if (sip_os_data ~= nil and (sip_os_data["os_class"]) ~= "") then
            packet_os_class = sip_os_data["os_class"]
        end

        if (sip_os_data ~= nil and (sip_os_data["os_vendor"]) ~= "") then
            packet_os_vendor = sip_os_data["os_vendor"]
        end

        if (sip_os_data ~= nil and (sip_os_data["device_type"]) ~= "") then
            packet_device_type = sip_os_data["device_type"]
        end

        if (sip_os_data ~= nil and (sip_os_data["device_vendor"]) ~= "") then
            packet_device_vendor = sip_os_data["device_vendor"]
        end

        sip_tree:add(osfinger_sip_full_name_F, tostring(packet_full_name))
        sip_tree:add(osfinger_sip_os_name_F, tostring(packet_os_name))
        sip_tree:add(osfinger_sip_os_class_F, tostring(packet_os_class))
        sip_tree:add(osfinger_sip_os_vendor_F, tostring(packet_os_vendor))
        sip_tree:add(osfinger_sip_device_type_F, tostring(packet_device_type))
        sip_tree:add(osfinger_sip_device_vendor_F, tostring(packet_device_vendor))

        --sip_tree:add(osfinger_sip_record_tree_F, sip_subtree)
    end

    osfinger_sip_dissector.sip_stream_table = osfinger.sip_stream_table
end

register_postdissector(cgs_sip_proto)

return osfinger_sip_dissector
