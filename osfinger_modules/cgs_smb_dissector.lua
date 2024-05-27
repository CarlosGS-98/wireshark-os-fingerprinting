----------------------------------------
-- script-name: cgs_smb_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023 - 2024, Carlos González Sanz
--
----------------------------------------

local osfinger = require("osfinger_utils")
local inspect = require("inspect")
local md5 = require("md5")

local osfinger_smb_dissector = {
    smb_stream_table = {}
}

-- Plugin constants/global variables
CGS_OS_SMB_PROTO = CGS_OS_PROTO .. "-smb"
SMB_NO_NAME = "NONE"

-- Fingerprinting protocol for SMB
local cgs_smb_proto = Proto(CGS_OS_SMB_PROTO, "OS Fingerprinting - SMB")

--- Fields for this SMB postdissector ---
local osfinger_smb_native_os = Field.new("smb.native_os")
local osfinger_smb_native_lanman = Field.new("smb.native_lanman")

-- Fields for the SMB dissection tree
local osfinger_smb_full_name_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".full_name", "Device/OS Full Name", "Can include version info about the given OS if it's one")  
local osfinger_smb_os_name_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".os_name", "OS Name")                                                      -- "name" (instead of "os_name", since it's empty most of the time)
local osfinger_smb_os_class_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".os_class", "OS Class", "The OS family that this system belongs to")      -- "os_class"
local osfinger_smb_os_vendor_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".os_vendor", "OS Vendor", "The OS vendor/distributor of this system")    -- "os_vendot"                   -- "device_name"
local osfinger_smb_device_type_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".device_type", "Device Type", "Device type/class")                     -- "device_type"
local osfinger_smb_device_vendor_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".device_vendor", "Device Vendor")

-- Add fields to the pseudo-protocol
cgs_smb_proto.fields = {osfinger_smb_full_name_F, osfinger_smb_os_name_F, osfinger_smb_os_class_F, osfinger_smb_os_vendor_F, osfinger_smb_device_type_F, osfinger_smb_device_vendor_F}

-- Base TCP/IP adresses and ports (in part to build a lookup table)
local osfinger_ip_src = Field.new("ip.src")
local osfinger_ip_dst = Field.new("ip.dst")
local osfinger_tcp_src = Field.new("tcp.srcport")
local osfinger_tcp_dst = Field.new("tcp.dstport")

-- Preload Satori's SMB signatures
local osfinger_smb_xml = osfinger.preloadXML(OSFINGER_SATORI_SMB)["SMB"]
local osfinger_smb_exact_list, osfinger_smb_partial_list = osfinger.signature_partition(osfinger_smb_xml, "SMB", "smb_tests")

--- Extra functions for this SMB postdissector ---
function osfinger_smb_dissector.osfinger_smb_match(cur_packet_data)
    local smb_signature_names = {}

    -- Because the signature info Satori provides us for SMB
    -- only contains SMB clients in "smb.xml",
    -- we must search both lists in order to find a given SMB match.
    --
    -- If we end up traversing the entire exact list
    -- without finding any match, then we should look up
    -- the partial list so as to try to find a match,
    -- which will have percentage data based on the weight
    -- of the current match as well as the number of records
    -- we retrieve from that list.

    local total_record_weight = 0
    local record_flag = false

    --- SMB Signatures ---
    -- SMB exact list traversal
    for index, elem in ipairs(osfinger_smb_exact_list) do
        record_flag = false
        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true

            if tostring(test_record["_attr"]["smbnativename"]) == tostring(cur_packet_data["native_os"]) then
                --elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(smb_signature_names, elem["info"])
                --total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                --return {smb_signature_names[1], total_record_weight, 1}   -- Since it's an exact match
                return smb_signature_names[1]

            elseif tostring(test_record["_attr"]["smbnativelanman"]) == tostring(cur_packet_data["native_lanman"]) then
                --elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(smb_signature_names, elem["info"])
                --total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                --return {smb_signature_names[1], total_record_weight, 1}   -- Since it's an exact match
                return smb_signature_names[1]
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if tostring(elem["tests"]["_attr"]["smbnativename"]) == tostring(cur_packet_data["native_os"]) then
                --elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(smb_signature_names, elem["info"])
                --total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                --return {smb_signature_names[1], total_record_weight, 1}   -- Since it's an exact match
                return smb_signature_names[1]

            elseif tostring(elem["tests"]["_attr"]["smbnativelanman"]) == tostring(cur_packet_data["native_lanman"]) then
                --elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(smb_signature_names, elem["info"])
                --total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                --return {smb_signature_names[1], total_record_weight, 1}   -- Since it's an exact match
                return smb_signature_names[1]
            end
        end
    end

    -- SMB partial list traversal (if we need to)
    for _, elem in ipairs(osfinger_smb_partial_list) do
        record_flag = false

        for _, test_record in ipairs(elem["tests"]) do
            record_flag = true

            if string.match(tostring(cur_packet_data["native_os"]), tostring(test_record["_attr"]["smbnativename"])) ~= nil then
            --if tostring(test_record["_attr"]["smbserver"]) == cur_packet_data["user_agent"] then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(smb_smbserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(test_record["_attr"]["weight"])
                total_matches = total_matches + 1

            elseif string.match(tostring(cur_packet_data["native_lanman"]), tostring(test_record["_attr"]["smbnativelanman"])) ~= nil then
                --if tostring(test_record["_attr"]["smbserver"]) == cur_packet_data["user_agent"] then
                elem["info"]["weight"] = tonumber(test_record["_attr"]["weight"])
                table.insert(smb_smbserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(test_record["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end

        if not record_flag then
            -- We have to use this as a fallback
            -- until we discover why our previous
            -- iterator gives up when the current
            -- record only contains a single test:

            if string.match(cur_packet_data["native_os"], tostring(elem["tests"]["_attr"]["smbnativename"])) ~= nil then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(smb_smbserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                total_matches = total_matches + 1

            elseif string.match(cur_packet_data["native_lanman"], tostring(elem["tests"]["_attr"]["smbnativelanman"])) ~= nil then
                elem["info"]["weight"] = tonumber(elem["tests"]["_attr"]["weight"])
                table.insert(smb_smbserver_names, elem["info"])
                total_record_weight = total_record_weight + tonumber(elem["tests"]["_attr"]["weight"])
                total_matches = total_matches + 1
            end
        end
    end

    -- if total_record_weight > 0 then
    --     -- table.sort(smb_signature_names, function(r1, r2)
    --     --     return r1["weight"] > r2["weight"]
    --     -- end)

    --     --return {smb_signature_names[1], total_record_weight, total_matches}
    --     return smb_signature_names[1]
    -- else
    --     return nil
    -- end
end

function cgs_smb_proto.dissector(buffer, pinfo, tree)
    -- Looking at Wireshark's documentation,
    -- it seems that we should only deal
    -- with TCP/UDP packets whose origin ports
    -- are 5061 or 5060, respectively
    -- (at least by default).

    local ip_src = osfinger_ip_src()
    local ip_dst = osfinger_ip_dst()
    local tcp_src = osfinger_tcp_src()
    local tcp_dst = osfinger_tcp_dst()

    local smb_native_os = osfinger_smb_native_os()
    local smb_native_lanman = osfinger_smb_native_lanman()

    if ip_src ~= nil
    and ip_dst ~= nil
    and tcp_src ~= nil
    and tcp_dst ~= nil
    and (tcp_src.value == 445 or tcp_dst.value == 445)
    and (smb_native_os ~= nil or smb_native_lanman ~= nil) then
        local smb_tree = tree:add(cgs_smb_proto, "OS Fingerprinting through SMB")
        local smb_os_data = {}

        -- We first calculate the stream ID based on the current addresses and ports
        local cur_stream_id = md5.sumhexa(tostring(ip_src) .. tostring(ip_dst) .. tostring(tcp_src) .. tostring(tcp_dst)) -- For consistency
        local temp_smb_sig = {}

        if osfinger.smb_stream_table[cur_stream_id] == nil then
            -- Build a new entry in the stream table
            -- with the current address and port info:

            osfinger.smb_stream_table[cur_stream_id] = {}

            -- Fill the current entry in the SMB stream table
            osfinger.smb_stream_table[cur_stream_id]["ip_pair"] = {
                src_ip = tostring(ip_src),
                dst_ip = tostring(ip_dst)
            }

            osfinger.smb_stream_table[cur_stream_id]["port_pair"] = {
                src_port = tostring(tcp_src),
                dst_port = tostring(tcp_dst)
            }

            -- After that, the next step is to build
            -- our signature (in p0f format) and compare it
            -- against the entries we have inside Satori's
            -- fingerprint database:

            temp_smb_sig = {
                native_os = tostring(smb_native_os.value) or SMB_NO_NAME,
                native_lanman = tostring(smb_native_lanman.value) or SMB_NO_NAME,
                -- Other options will be added later if they exist in the current packet
            }

            -- Let's check what we got back
            smb_os_data = osfinger_smb_dissector.osfinger_smb_match(temp_smb_sig)

            if smb_os_data ~= nil then
                -- Store the result in the current stream record
                osfinger.smb_stream_table[cur_stream_id]["os_data"] = smb_os_data

            end
            -- (...)
        else
            -- If we get here, we just assume that
            -- this packet belongs to a previous stream:

            if osfinger.smb_stream_table[cur_stream_id]["os_data"] ~= nil then
                smb_os_data = osfinger.smb_stream_table[cur_stream_id]["os_data"]
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

        if (smb_os_data ~= nil and (smb_os_data["name"]) ~= "") then
            packet_full_name = smb_os_data["name"]
        end

        if (smb_os_data ~= nil and (smb_os_data["os_name"]) ~= "") then
            packet_os_name = smb_os_data["os_name"]
        end

        if (smb_os_data ~= nil and (smb_os_data["os_class"]) ~= "") then
            packet_os_class = smb_os_data["os_class"]
        end

        if (smb_os_data ~= nil and (smb_os_data["os_vendor"]) ~= "") then
            packet_os_vendor = smb_os_data["os_vendor"]
        end

        if (smb_os_data ~= nil and (smb_os_data["device_type"]) ~= "") then
            packet_device_type = smb_os_data["device_type"]
        end

        if (smb_os_data ~= nil and (smb_os_data["device_vendor"]) ~= "") then
            packet_device_vendor = smb_os_data["device_vendor"]
        end

        smb_tree:add(osfinger_smb_full_name_F, tostring(packet_full_name))
        smb_tree:add(osfinger_smb_os_name_F, tostring(packet_os_name))
        smb_tree:add(osfinger_smb_os_class_F, tostring(packet_os_class))
        smb_tree:add(osfinger_smb_os_vendor_F, tostring(packet_os_vendor))
        smb_tree:add(osfinger_smb_device_type_F, tostring(packet_device_type))
        smb_tree:add(osfinger_smb_device_vendor_F, tostring(packet_device_vendor))
    end

    osfinger_smb_dissector.smb_stream_table = osfinger.smb_stream_table
end

register_postdissector(cgs_smb_proto)

return osfinger_smb_dissector
