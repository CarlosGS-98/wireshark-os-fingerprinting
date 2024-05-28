----------------------------------------
-- script-name: cgs_dns_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023 - 2024, Carlos González Sanz
--
----------------------------------------

local osfinger = require("osfinger_utils")
local fun = require("fun")
local inspect = require("inspect")
local md5 = require("md5")

local osfinger_dns_dissector = {}

-- Plugin constants/global variables
CGS_OS_DNS_PROTO = CGS_OS_PROTO .. "-dns"
DNS_NO_NAME = "NONE"

-- Fingerprinting protocol for DNS
local cgs_dns_proto = Proto(CGS_OS_DNS_PROTO, "OS Fingerprinting - DNS")

--- Fields for this DNS postdissector ---
local osfinger_dns_id = Field.new("dns.id")
local osfinger_dns_query_name = Field.new("dns.qry.name")
local osfinger_dns_response_name = Field.new("dns.resp.name")

-- Fields for the DNS dissection tree
local osfinger_dns_full_name_F = ProtoField.string(CGS_OS_DNS_PROTO .. ".full_name", "Device/OS Full Name", "Can include version info about the given OS if it's one")  
local osfinger_dns_os_name_F = ProtoField.string(CGS_OS_DNS_PROTO .. ".os_name", "OS Name")                                                      -- "name" (instead of "os_name", since it's empty most of the time)
local osfinger_dns_os_class_F = ProtoField.string(CGS_OS_DNS_PROTO .. ".os_class", "OS Class", "The OS family that this system belongs to")      -- "os_class"
local osfinger_dns_os_vendor_F = ProtoField.string(CGS_OS_DNS_PROTO .. ".os_vendor", "OS Vendor", "The OS vendor/distributor of this system")    -- "os_vendot"                   -- "device_name"
local osfinger_dns_device_type_F = ProtoField.string(CGS_OS_DNS_PROTO .. ".device_type", "Device Type", "Device type/class")                     -- "device_type"
local osfinger_dns_device_vendor_F = ProtoField.string(CGS_OS_DNS_PROTO .. ".device_vendor", "Device Vendor")
local osfinger_dns_record_tree_F = ProtoField.string(CGS_OS_DNS_PROTO .. ".record", "Current Match")

-- Add fields to the pseudo-protocol
cgs_dns_proto.fields = {osfinger_dns_full_name_F, osfinger_dns_os_name_F, osfinger_dns_os_class_F, osfinger_dns_os_vendor_F, osfinger_dns_device_type_F, osfinger_dns_device_vendor_F, osfinger_dns_record_tree_F}

-- Base TCP/IP adresses and ports (in part to build a lookup table)
local osfinger_ip_src = Field.new("ip.src")
local osfinger_ip_dst = Field.new("ip.dst")
local osfinger_tcp_src = Field.new("tcp.srcport")
local osfinger_tcp_dst = Field.new("tcp.dstport")
local osfinger_udp_src = Field.new("udp.srcport")
local osfinger_udp_dst = Field.new("udp.dstport")

--- Flag fields for this DNS postdissector ---
local osfinger_dns_flags = Field.new("dns.flags")    -- We expect this to be a byte array (maybe)

-- Preload Satori's DNS signatures
local osfinger_dns_xml = osfinger.preloadXML(OSFINGER_SATORI_DNS)["DNS"]
local osfinger_dns_exact_list, osfinger_dns_partial_list = osfinger.signature_partition(osfinger_dns_xml, "DNS", "dns_tests")

function osfinger_dns_dissector.osfinger_dns_match(cur_packet_data, finger_db)
    -- Get both the query and response domain names
    local dns_response_names = {}

    -- Because the signature info Satori provides us for DNS
    -- only contains domain names, we must search both lists
    -- in order to find a given DNS match.
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

    -- DNS exact list traversal
    for _, elem in ipairs(osfinger_dns_exact_list) do
        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true
            if tostring(test_record["_attr"]["dns"]) == tostring(cur_packet_data["response_name"]) then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(dns_response_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                return {dns_response_names[1], total_record_weight, 1}   -- Since it's an exact match
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if tostring(elem["tests"]["_attr"]["dns"]) == tostring(cur_packet_data["response_name"]) then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(dns_response_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                return {dns_response_names[1], total_record_weight, 1}   -- Since it's an exact match
            end
        end
    end

    -- DNS partial list traversal (if we need to)
    for _, elem in ipairs(osfinger_dns_partial_list) do
        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true

            if string.match(tostring(cur_packet_data["response_name"]), tostring(test_record["_attr"]["dns"])) ~= nil then
            --if tostring(test_record["_attr"]["dns"]) == cur_packet_data["response_name"] then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(dns_response_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(test_record["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if string.match(cur_packet_data["response_name"], tostring(elem["tests"]["_attr"]["dns"])) ~= nil then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(dns_response_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end
    end

    if total_record_weight > 0 then
        -- table.sort(dns_response_names, function(r1, r2)
        --     return r1["weight"] > r2["weight"]
        -- end)
        --return {dns_response_names[1], total_record_weight, total_matches}
        return dns_response_names[1]
    else
        return nil
    end
end

function cgs_dns_proto.dissector(buffer, pinfo, tree)
    -- (WIP) --
    local dns_id = osfinger_dns_id()
    local query_name = osfinger_dns_query_name()
    local response_name = osfinger_dns_response_name()

    -- Looking at Python Satori's code (),
    -- it seems that we should only deal
    -- with DNS packets whose flags are set
    -- to either 0x0100 (DNS Standard Query (= 256))
    -- or 0x8180 (DNS Standard Response (= 33152))

    local ip_src = osfinger_ip_src()
    local ip_dst = osfinger_ip_dst()
    local tcp_src = osfinger_tcp_src()
    local tcp_dst = osfinger_tcp_dst()
    local udp_src = osfinger_udp_src()
    local udp_dst = osfinger_udp_dst()
    local dns_flags = osfinger_dns_flags()

    -- Check which transport layer protocol was used
    local cur_src_port = udp_src or tcp_src
    local cur_dst_port = udp_dst or tcp_dst

    if dns_id ~= nil and ip_src ~= nil and ip_dst ~= nil and (dns_flags.value == 0x100 or dns_flags.value == 0x8180) then
        local dns_tree = tree:add(cgs_dns_proto, "OS Fingerprinting through DNS")
        local dns_os_data = {}

        -- We first calculate the stream ID based on the current addresses and ports
        local cur_stream_id = md5.sumhexa(tostring(ip_src) .. tostring(ip_dst) .. tostring(cur_src_port) .. tostring(cur_dst_port)) -- For consistency
        local temp_dns_sig = {}

        if osfinger.dns_stream_table[cur_stream_id] == nil then
            -- Build a new entry in the stream table
            -- with the current address and port info:

            osfinger.dns_stream_table[cur_stream_id] = {}

            -- Fill the current entry in the DNS stream table
            osfinger.dns_stream_table[cur_stream_id]["ip_pair"] = {
                src_ip = tostring(ip_src),
                dst_ip = tostring(ip_dst)
            }

            osfinger.dns_stream_table[cur_stream_id]["port_pair"] = {
                src_port = tostring(cur_src_port),
                dst_port = tostring(cur_dst_port)
            }

            osfinger.dns_stream_table[cur_stream_id]["dns_id"] = tostring(dns_id)

            -- After that, the next step is to build
            -- our signature (in p0f format) and compare it
            -- against the entries we have inside Satori's
            -- fingerprint database:

            temp_dns_sig = {
                dns_id = tonumber(dns_id.value),
                query_name = tostring(query_name.value) or DNS_NO_NAME,
                response_name = tostring(response_name.value) or DNS_NO_NAME
                -- Other options will be added later if they exist in the current packet
            }

            -- Let's check what we got back
            dns_os_data = osfinger_dns_dissector.osfinger_dns_match(temp_dns_sig, osfinger_dns_xml)

            if dns_os_data ~= nil then
                -- Store the result in the current stream record
                osfinger.dns_stream_table[cur_stream_id]["os_data"] = dns_os_data
            end
            -- (...)
        else
            -- If we get here, we just assume that
            -- this packet belongs to a previous stream:

            --- [TODO]: Fetch SIP signature info for the current packet ---
            if osfinger.dns_stream_table[cur_stream_id]["os_data"] ~= nil then
                dns_os_data = osfinger.dns_stream_table[cur_stream_id]["os_data"]
            end
        end

        -- After all those checks, we finally display
        -- all the relevant info from our current packet:

        -- local dns_subtree = dns_tree:add(
        --     "Best of " .. tostring(dns_os_data[3]) .. " matches" .. " (" .. string.format("%.2f", tostring((tonumber(dns_os_data[1]["weight"]) / tonumber(dns_os_data[2])) * 100)) .. " %)"
        -- )

        local packet_full_name = "Unknown"
        local packet_os_name = "Unknown"
        local packet_os_class = "Unknown"
        local packet_os_vendor = "Unknown"
        local packet_device_type = "Unknown"
        local packet_device_vendor = "Unknown"

        if (dns_os_data ~= nil and tostring(dns_os_data["name"]) ~= "") then
            packet_full_name = tostring(dns_os_data["name"])
        end

        if (dns_os_data ~= nil and tostring(dns_os_data["os_name"]) ~= "") then
            packet_os_name = tostring(dns_os_data["os_name"])
        end

        if (dns_os_data ~= nil and tostring(dns_os_data["os_class"]) ~= "") then
            packet_os_class = tostring(dns_os_data["os_class"])
        end

        if (dns_os_data ~= nil and tostring(dns_os_data["os_vendor"]) ~= "") then
            packet_os_vendor = tostring(dns_os_data["os_vendor"])
        end

        if (dns_os_data ~= nil and tostring(dns_os_data["device_type"]) ~= "") then
            packet_device_type = tostring(dns_os_data["device_type"])
        end

        if (dns_os_data ~= nil and tostring(dns_os_data["device_vendor"]) ~= "") then
            packet_device_vendor = tostring(dns_os_data["device_vendor"])
        end

        -- Create a subtree for our current DNS match
        -- local dns_subtree, _ = dns_tree:add_packet_field{
        --     protofield = osfinger_dns_record_tree_F,
        --     label = "Best of " .. tostring(dns_os_data[3]) .. " matches" .. " (" .. string.format("%.2f", tostring((tonumber(dns_os_data[1]["weight"]) / tonumber(dns_os_data[2])) * 100)) .. " %)"
        -- }

        -- if dns_os_data[3] ~= nil then

        --     dns_tree = tree:add(cgs_dns_proto, "OS Fingerprinting through DNS [Best of " .. tostring(dns_os_data[3]) .. " match(es)" .. " (" .. string.format("%.2f", tostring((tonumber(dns_os_data[1]["weight"]) / tonumber(dns_os_data[2])) * 100)) .. " %)]")
        -- end

        dns_tree:add(osfinger_dns_full_name_F, tostring(packet_full_name))
        dns_tree:add(osfinger_dns_os_name_F, tostring(packet_os_name))
        dns_tree:add(osfinger_dns_os_class_F, tostring(packet_os_class))
        dns_tree:add(osfinger_dns_os_vendor_F, tostring(packet_os_vendor))
        dns_tree:add(osfinger_dns_device_type_F, tostring(packet_device_type))
        dns_tree:add(osfinger_dns_device_vendor_F, tostring(packet_device_vendor))

        --dns_tree:add(osfinger_dns_record_tree_F, dns_subtree)
    end

    osfinger_dns_dissector.dns_stream_table = osfinger.dns_stream_table
end

register_postdissector(cgs_dns_proto)

-- local udp_port_table = DissectorTable.get("udp.port")
-- local dns_port_table = udp_port_table:get_dissector(53)
-- dns_port_table:add("-", cgs_dns_proto)

return osfinger_dns_dissector
