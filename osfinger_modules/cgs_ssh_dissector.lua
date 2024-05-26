----------------------------------------
-- script-name: cgs_ssh_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023 - 2024, Carlos González Sanz
--
----------------------------------------

local osfinger = require("osfinger_utils")
local inspect = require("inspect")
local md5 = require("md5")

local osfinger_ssh_dissector = {
    ssh_stream_table = {}
}

-- Plugin constants/global variables
CGS_OS_SSH_PROTO = CGS_OS_PROTO .. "-ssh"
SSH_NO_NAME = "NONE"

-- Fingerprinting protocol for SSH
local cgs_ssh_proto = Proto(CGS_OS_SSH_PROTO, "OS Fingerprinting - SSH")

--- Fields for this SSH postdissector ---
local osfinger_ssh_protocol = Field.new("ssh.protocol")

-- Fields for the SSH dissection tree
local osfinger_ssh_full_name_F = ProtoField.string(CGS_OS_SSH_PROTO .. ".full_name", "Device/OS Full Name", "Can include version info about the given OS if it's one")  
local osfinger_ssh_os_name_F = ProtoField.string(CGS_OS_SSH_PROTO .. ".os_name", "OS Name")                                                      -- "name" (instead of "os_name", since it's empty most of the time)
local osfinger_ssh_os_class_F = ProtoField.string(CGS_OS_SSH_PROTO .. ".os_class", "OS Class", "The OS family that this system belongs to")      -- "os_class"
local osfinger_ssh_os_vendor_F = ProtoField.string(CGS_OS_SSH_PROTO .. ".os_vendor", "OS Vendor", "The OS vendor/distributor of this system")    -- "os_vendot"                   -- "device_name"
local osfinger_ssh_device_type_F = ProtoField.string(CGS_OS_SSH_PROTO .. ".device_type", "Device Type", "Device type/class")                     -- "device_type"
local osfinger_ssh_device_vendor_F = ProtoField.string(CGS_OS_SSH_PROTO .. ".device_vendor", "Device Vendor")

-- Add fields to the pseudo-protocol
cgs_ssh_proto.fields = {osfinger_ssh_full_name_F, osfinger_ssh_os_name_F, osfinger_ssh_os_class_F, osfinger_ssh_os_vendor_F, osfinger_ssh_device_type_F, osfinger_ssh_device_vendor_F}

-- Base TCP/IP adresses and ports (in part to build a lookup table)
local osfinger_ip_src = Field.new("ip.src")
local osfinger_ip_dst = Field.new("ip.dst")
local osfinger_tcp_src = Field.new("tcp.srcport")
local osfinger_tcp_dst = Field.new("tcp.dstport")

-- Preload Satori's SSH signatures
local osfinger_ssh_xml = osfinger.preloadXML(OSFINGER_SATORI_SSH)["SSH"]
local osfinger_ssh_exact_list, osfinger_ssh_partial_list = osfinger.signature_partition(osfinger_ssh_xml, "SSH", "ssh_tests")

-- print("Exact SSH List = " .. inspect(osfinger_ssh_exact_list))
-- print("Partial SSH List = " .. inspect(osfinger_ssh_partial_list))

--- Extra functions for this SSH postdissector ---
function osfinger_ssh_dissector.osfinger_ssh_match(cur_packet_data)
    local ssh_protocol_names = {}

    -- Because the signature info Satori provides us for SSH
    -- only contains server names in "ssh.xml",
    -- we must search both lists in order to find a given SSH server match.
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

    --- SSH ---
    -- SSH exact list traversal
    for index, elem in ipairs(osfinger_ssh_exact_list) do
        record_flag = false
        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true

            print(tostring(test_record["_attr"]["ssh"]) .. "(VS)" .. tostring(cur_packet_data["ssh_protocol"]))

            if tostring(test_record["_attr"]["ssh"]) == tostring(cur_packet_data["ssh_protocol"]) then
                --elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(ssh_protocol_names, elem["info"])
                --total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                --return {ssh_protocol_names[1], total_record_weight, 1}   -- Since it's an exact match
                return ssh_protocol_names[1]
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if tostring(elem["tests"]["_attr"]["ssh"]) == tostring(cur_packet_data["ssh_protocol"]) then
                --elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(ssh_protocol_names, elem["info"])
                --total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                --return {ssh_protocol_names[1], total_record_weight, 1}   -- Since it's an exact match
                print(inspect(ssh_protocol_names[1]))
                return ssh_protocol_names[1]
            end
        end
    end

    print("Responses (After exact matches (SSH)) = " .. tostring(inspect(ssh_protocol_names)))

    -- SSH partial list traversal (if we need to)
    for _, elem in ipairs(osfinger_ssh_partial_list) do
        record_flag = false
        --print("Current partial element = " .. tostring(inspect(elem)))

        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true

            if string.match(tostring(cur_packet_data["ssh_protocol"]), tostring(test_record["_attr"]["ssh"])) ~= nil then
            --if tostring(test_record["_attr"]["ssh"]) == cur_packet_data["user_agent"] then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(ssh_protocol_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(test_record["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if string.match(cur_packet_data["ssh_protocol"], tostring(elem["tests"]["_attr"]["ssh"])) ~= nil then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(ssh_protocol_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end
    end

    print("Responses (After partial matches (SSH)) = " .. tostring(inspect(ssh_protocol_names)))

    if total_record_weight > 0 then
        -- table.sort(ssh_protocol_names, function(r1, r2)
        --     return r1["weight"] > r2["weight"]
        -- end)

        -- print(inspect(ssh_protocol_names))

        --return {ssh_protocol_names[1], total_record_weight, total_matches}
        return ssh_protocol_names[1]
    else
        return nil
    end
end

function cgs_ssh_proto.dissector(buffer, pinfo, tree)
    -- Looking at Wireshark's documentation,
    -- it seems that we should only deal
    -- with TCP packets whose origin and destination ports
    -- are equal to 22 (at least by default).

    local ip_src = osfinger_ip_src()
    local ip_dst = osfinger_ip_dst()
    local tcp_src = osfinger_tcp_src()
    local tcp_dst = osfinger_tcp_dst()

    local ssh_protocol = osfinger_ssh_protocol()

    if ip_src ~= nil
    and ip_dst ~= nil
    and tcp_src ~= nil
    and tcp_dst ~= nil
    and ssh_protocol ~= nil -- Because this gives us the SSH client used (if our packet isn't encrypted)
    and (tcp_src.value == 22 or tcp_dst.value == 22) then
        
        local ssh_tree = tree:add(cgs_ssh_proto, "OS Fingerprinting through SSH")
        local ssh_os_data = {}

        -- We first calculate the stream ID based on the current addresses and ports
        local cur_stream_id = md5.sumhexa(tostring(ip_src) .. tostring(ip_dst) .. tostring(tcp_src) .. tostring(tcp_dst)) -- For consistency
        local temp_ssh_sig = {}

        if osfinger.ssh_stream_table[cur_stream_id] == nil then
            -- Build a new entry in the stream table
            -- with the current address and port info:

            osfinger.ssh_stream_table[cur_stream_id] = {}
            print("New SSH stream ID detected: " .. cur_stream_id)
            print("Address pair: [" .. tostring(ip_src) .. ":" .. tostring(tcp_src) .. ", " .. tostring(ip_dst) .. ":" .. tostring(tcp_dst) .. "]")

            -- Fill the current entry in the SSH stream table
            osfinger.ssh_stream_table[cur_stream_id]["ip_pair"] = {
                src_ip = tostring(ip_src),
                dst_ip = tostring(ip_dst)
            }

            osfinger.ssh_stream_table[cur_stream_id]["port_pair"] = {
                src_port = tostring(tcp_src),
                dst_port = tostring(tcp_dst)
            }

            print(inspect(osfinger.ssh_stream_table[cur_stream_id]))

            -- After that, the next step is to build
            -- our signature (in p0f format) and compare it
            -- against the entries we have inside Satori's
            -- fingerprint database:

            temp_ssh_sig = {
                ssh_protocol = tostring(ssh_protocol.value) or SSH_NO_NAME,
                -- Other options will be added later if they exist in the current packet
            }

            print(inspect(temp_ssh_sig) .. "\n")

            -- Let's check what we got back
            ssh_os_data = osfinger_ssh_dissector.osfinger_ssh_match(temp_ssh_sig)
            --print("Do we have SSH data?: " .. tostring(ssh_os_data ~= nil))
            if ssh_os_data ~= nil then
                -- Store the result in the current stream record
                osfinger.ssh_stream_table[cur_stream_id]["os_data"] = ssh_os_data
                --print(inspect(osfinger.ssh_stream_table[cur_stream_id]["os_data"]))
            end
            -- (...)
        else
            -- If we get here, we just assume that
            -- this packet belongs to a previous stream:

            --- [TODO]: Fetch SSH signature info for the current packet ---
            if osfinger.ssh_stream_table[cur_stream_id]["os_data"] ~= nil then
                ssh_os_data = osfinger.ssh_stream_table[cur_stream_id]["os_data"]
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

        if (ssh_os_data ~= nil and (ssh_os_data["name"]) ~= "") then
            packet_full_name = ssh_os_data["name"]
        end

        if (ssh_os_data ~= nil and (ssh_os_data["os_name"]) ~= "") then
            packet_os_name = ssh_os_data["os_name"]
        end

        if (ssh_os_data ~= nil and (ssh_os_data["os_class"]) ~= "") then
            packet_os_class = ssh_os_data["os_class"]
        end

        if (ssh_os_data ~= nil and (ssh_os_data["os_vendor"]) ~= "") then
            packet_os_vendor = ssh_os_data["os_vendor"]
        end

        if (ssh_os_data ~= nil and (ssh_os_data["device_type"]) ~= "") then
            packet_device_type = ssh_os_data["device_type"]
        end

        if (ssh_os_data ~= nil and (ssh_os_data["device_vendor"]) ~= "") then
            packet_device_vendor = ssh_os_data["device_vendor"]
        end

        ssh_tree:add(osfinger_ssh_full_name_F, tostring(packet_full_name))
        ssh_tree:add(osfinger_ssh_os_name_F, tostring(packet_os_name))
        ssh_tree:add(osfinger_ssh_os_class_F, tostring(packet_os_class))
        ssh_tree:add(osfinger_ssh_os_vendor_F, tostring(packet_os_vendor))
        ssh_tree:add(osfinger_ssh_device_type_F, tostring(packet_device_type))
        ssh_tree:add(osfinger_ssh_device_vendor_F, tostring(packet_device_vendor))
    end

    osfinger_ssh_dissector.ssh_stream_table = osfinger.ssh_stream_table
end

register_postdissector(cgs_ssh_proto)

return osfinger_ssh_dissector
