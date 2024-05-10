----------------------------------------
-- script-name: cgs_tcp_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023, Carlos González Sanz
--
----------------------------------------

local osfinger = require("osfinger_utils")
local fun = require("fun")
local inspect = require("inspect")
local md5 = require("md5")

local osfinger_tcp_dissector = {
    tcp_stream_table = {}
}

-- Plugin constants/global variables
CGS_OS_TCP_PROTO = CGS_OS_PROTO .. "-tcp"

-- Fingerprinting protocol for TCP
local cgs_tcp_proto = Proto(CGS_OS_TCP_PROTO, "OS Fingerprinting - TCP")

--- Fields for this TCP postdissector ---
-- TCP/IP adresses and ports (in part to build a lookup table)
local osfinger_ip_src = Field.new("ip.src")
local osfinger_ip_dst = Field.new("ip.dst")
local osfinger_tcp_src = Field.new("tcp.srcport")
local osfinger_tcp_dst = Field.new("tcp.dstport")

-- More specific TCP parameters
local osfinger_tcp_wsize = Field.new("tcp.window_size")
local osfinger_tcp_mss = Field.new("tcp.options.mss_val")
local osfinger_ip_ttl = Field.new("ip.ttl")
local osfinger_tcp_wscale = Field.new("tcp.options.wscale.shift")
local osfinger_ip_df = Field.new("ip.flags.df")
local osfinger_tcp_len = Field.new("tcp.len")

-- Judging by Satori's own signatures, only the
-- SYN and ACK flags are ever taken into account:

local osfinger_tcp_ack = Field.new("tcp.flags.ack")
local osfinger_tcp_ack_num = Field.new("tcp.ack")
local osfinger_tcp_syn = Field.new("tcp.flags.syn")
local osfinger_tcp_fin = Field.new("tcp.flags.fin")      -- To free entries from the lookup table whenever we're sure that a given TCP connection has ended
local osfinger_tcp_urgent = Field.new("tcp.flags.urg")
local osfinger_tcp_flags = Field.new("tcp.flags")        -- To detect packet anomalies

local osfinger_tcp_options = Field.new("tcp.options")

-- Header parameters
local osfinger_ip_header_len = Field.new("ip.hdr_len")
local osfinger_ip_id = Field.new("ip.id")
local osfinger_ip_length = Field.new("ip.len")
local osfinger_tcp_header_len = Field.new("tcp.hdr_len")

-- Create the fields for our "protocol"
local osfinger_tcp_full_name_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".full_name", "Device/OS Full Name", "Can include version info about the given OS if it's one")  
local osfinger_tcp_os_name_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".os_name", "OS Name")                                                      -- "name" (instead of "os_name", since it's empty most of the time)
local osfinger_tcp_os_class_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".os_class", "OS Class", "The OS family that this system belongs to")      -- "os_class"
local osfinger_tcp_os_vendor_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".os_vendor", "OS Vendor", "The OS vendor/distributor of this system")    -- "os_vendot"
--local osfinger_tcp_device_name_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".device_name", "Device", "Device that runs this OS")                   -- "device_name"
local osfinger_tcp_device_type_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".device_type", "Device Type", "Device type/class")                     -- "device_type"
local osfinger_tcp_device_vendor_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".device_vendor", "Device Vendor")                                    -- "device_vendor"
-- (...)

-- Add fields to the pseudo-protocol
cgs_tcp_proto.fields = {osfinger_tcp_full_name_F, osfinger_tcp_os_name_F, osfinger_tcp_os_class_F, osfinger_tcp_os_vendor_F, osfinger_tcp_device_name_F, osfinger_tcp_device_type_F, osfinger_tcp_device_vendor_F}

-- Preload Satori's TCP signatures
local osfinger_tcp_xml = osfinger.preloadXML(OSFINGER_SATORI_TCP)

-- Make a partition of all TCP signatures based on their match type
local function osfinger_tcp_signature_partition(finger_db)
    -- Traverse the entire TCP database to correctly
    -- store exact signatures matches and partial ones
    -- on separate tables, which will improve performance
    -- when performing database lookups:

    local finger_root = finger_db["TCP"]["fingerprints"]["fingerprint"]
    local exact_list, partial_list = {}, {}

    for _, record in ipairs(finger_root) do
        local exact_tests = {}
        local partial_tests = {}

        -- Manual filtering due to massive bugs
        -- when using LuaFun's API with our DB:

        if record["tcp_tests"]["test"] ~= nil then
            for _, elem in ipairs(record["tcp_tests"]["test"]) do
                if elem["_attr"]["matchtype"] == "exact" then
                    table.insert(exact_tests, elem)
                else
                    table.insert(partial_tests, elem)
                end
            end

            -- Add the current results to both tables
            -- if we extract any corresponding matches:

            if next(exact_tests) ~= nil then
                table.insert(exact_list, {info = record["_attr"], tests = exact_tests})
            end

            if next(partial_tests) ~= nil then
                table.insert(partial_list, {info = record["_attr"], tests = partial_tests})
            end
        end
    end

    return exact_list, partial_list
end

local osfinger_tcp_exact_list, osfinger_tcp_partial_list = osfinger.signature_partition(osfinger_tcp_xml, "TCP", "tcp_tests")
--print(inspect(osfinger_tcp_exact_list))

-- Function that allows us to build p0f TCP signatures
-- based on the captured data (to compare it later against
-- Satori's TCP fingerprint database):

function osfinger_tcp_dissector.osfinger_build_tcp_signature(packet_data)
    -- We'll store some of the info contained inside packet_data
    -- inside a new anonymous table so we can later concatenate its contents
    -- (ideally with ":" as the separator).
    --
    -- Additionally, we'll use two additional tables to create the
    -- whole TCP signature (in p0fv2 format):
    -- one for storing TCP options and another one for TCP quirks.

    -- Temporary table to hold the first part of our signature:
    -- (FORMAT): "window_size:ttl:df_bit:total_header_length"
    --print("Options table = " .. tostring(packet_data["options"]))

    local tcp_sig_first = table.concat({
        tostring(packet_data["window_size"]),
        tostring(packet_data["ttl"]),
        tostring(packet_data["df_bit"] and 1 or 0),
        tostring(tonumber(packet_data["ip_header_len"]) + tonumber(packet_data["tcp_header_len"]))
    }, ":")

    --print("First part = " .. tcp_sig_first)

    -- The second part of our signature will contain
    -- all TCP options that have been specified
    -- for the current packet. In order to get these,
    -- we'll have to treat tcp.options as a ByteArray,
    -- which enables us to traverse them in the same
    -- exact order they were sent over the network:

    local tcp_sig_second = ":"
    local tcp_timestamp_echo = nil
    local tcp_timestamp_reply = nil

    -- The options will be a list of comma-separated values
    if packet_data["options"] ~= "" then
        local option_index = 0

        -- Guaranteed single-pass traversal of the TCP options array
        repeat
            -- [NOTE]: This snippet is similar to https://github.com/xnih/satori/blob/master/satoriTCP.py,
            -- only written in Lua and with some syntactic modifications.
            if option_index > 0 then
                tcp_sig_second = tcp_sig_second .. ","
            end

            -- The current byte will be, in this case, our TCP kind
            local cur_tcp_kind = tonumber(packet_data["options"]:get_index(option_index))

            if cur_tcp_kind == 0 then               -- End
                tcp_sig_second = tcp_sig_second .. "E"
                option_index = option_index + 1
            elseif cur_tcp_kind == 1 then           -- NOP
                tcp_sig_second = tcp_sig_second .. "N"
                option_index = option_index + 1
            elseif cur_tcp_kind == 2 then           -- MSS
                tcp_sig_second = tcp_sig_second .. "M" .. tostring(tonumber(packet_data["options"]:uint(option_index + 2, 2)))
                option_index = option_index + 4
            elseif cur_tcp_kind == 3 then           -- Window Scale
                -- We already have this, so we concatenate it directly
                tcp_sig_second = tcp_sig_second .. "W" .. tostring(tonumber(packet_data["options"]:uint(option_index + 2, 1)))
                option_index = option_index + 3
            elseif cur_tcp_kind == 4 then           -- SACK Permitted
                tcp_sig_second = tcp_sig_second .. "S"
                option_index = option_index + 2
            elseif cur_tcp_kind == 5 then           -- SACK
                tcp_sig_second = tcp_sig_second .. "K"
                option_index = option_index + tonumber(packet_data["options"]:get_index(option_index + 1))
            elseif cur_tcp_kind == 6 then          -- Echo
                tcp_sig_second = tcp_sig_second .. "J"
                option_index = option_index + 6
            elseif cur_tcp_kind == 7 then          -- Echo Reply
                tcp_sig_second = tcp_sig_second .. "F"
                option_index = option_index + 6
            elseif cur_tcp_kind == 8 then          -- Timestamps
                tcp_sig_second = tcp_sig_second .. "T"

                -- Get timestamp data in case there's
                -- an anomaly in the current packet:

                tcp_timestamp_echo = tonumber(packet_data["options"]:uint(option_index + 2, 4))
                tcp_timestamp_reply = tonumber(packet_data["options"]:uint(option_index + 6, 4))

                option_index = option_index + 10
            elseif cur_tcp_kind == 9 then          -- Partial Order Connection
                tcp_sig_second = tcp_sig_second .. "P"
                option_index = option_index + 2
            elseif cur_tcp_kind == 10 then         -- Partial Order Service
                tcp_sig_second = tcp_sig_second .. "R"
                option_index = option_index + 3
            else
                tcp_sig_second = tcp_sig_second .. "U"
                option_index = option_index + 1
            end
        until option_index >= packet_data["options"]:len()

        tcp_sig_second = tcp_sig_second .. ":"
	else
        tcp_sig_second = ":*:"    -- "*" as a wildcard for searching later inside the fingerprint database
    end

    --print("Second part = " .. tcp_sig_first .. tcp_sig_second)

    -- The third and last part of our signature
    -- will consist of quirks that the current packet
    -- presents, if there are any present:

    local tcp_sig_third = ""

    -- Heavily based off https://github.com/xnih/satori/blob/master/satoriTCP.py --
    if (packet_data["options"] ~= "") and (tonumber(packet_data["options"]:get_index(packet_data["options"]:len() - 1)) == 0) then
        tcp_sig_third = tcp_sig_third .. "P"
    end
    --print("P-Check tested")

    if packet_data["ip_id"] == 0 then
        tcp_sig_third = tcp_sig_third .. "Z"
    end
    --print("Z-Check tested")

    if packet_data["ip_header_len"] > 20 then
        tcp_sig_third = tcp_sig_third .. "I"
    end
    --print("I-Check tested")

    if (packet_data["ip_length"] - packet_data["ip_header_len"] - packet_data["tcp_header_len"]) ~= 0 then
        tcp_sig_third = tcp_sig_third .. "D"
    end
    --print("D-Check tested")

    if packet_data["urg_bit"] then
        tcp_sig_third = tcp_sig_third .. "U"
    end
    --print("U-Check tested")

    if (packet_data["syn_check"] or (packet_data["syn_check"] and packet_data["ack_check"])) and (packet_data["ack_num"] ~= 0) then
        tcp_sig_third = tcp_sig_third .. "A"
    end
    --print("A-Check tested")

    if tcp_timestamp_reply ~= nil and tcp_timestamp_echo ~= nil then
        local timestamp_delta = tcp_timestamp_reply - tcp_timestamp_echo

        if (packet_data["syn_flag"] and timestamp_delta ~= 0) or (packet_data["syn_flag"] and packet_data["ack_flag"] and tcp_timestamp_echo ~= nil and tcp_timestamp_reply ~= nil) then
            tcp_sig_third = tcp_sig_third .. "T"
        end
    end
   
    --print("T-Check tested")

    -- Lua doesn't support bitwise operators until Lua 5.3
    if (bit32.band(packet_data["flag_array"], 0xFFED)) ~= 0 then  -- SYN+ACK = 0x12 = 18
        tcp_sig_third = tcp_sig_third .. "F"
    end
    --print("F-Check tested")

    if tcp_sig_third == "" then
        tcp_sig_third = "."
    end
    --print(".-Check tested")

    --print("Third part = " .. tcp_sig_first .. tcp_sig_second .. tcp_sig_third)

    return tcp_sig_first .. tcp_sig_second .. tcp_sig_third
end

-- Function that tries to find a signature match between
-- the current frame and all TCP signatures:

function osfinger_tcp_dissector.osfinger_tcp_match(cur_packet_data, finger_db)
    -- Before filtering all fingerprints to look at
    -- those that match certain parameters, we must extract
    -- the main root of the TCP DB table to both ease the workload
    -- on this very function and prevent accidentally overwriting the DB:

    local tcp_lookup_db = nil
    local tcp_sig_tokens = {}

    -- Filtering parameters
    local ack_filter = (cur_packet_data["ack_bit"] ~= nil) and cur_packet_data["ack_bit"]
    local syn_filter = (cur_packet_data["syn_bit"] ~= nil) and cur_packet_data["syn_bit"]

    print("Signature = \"" .. cur_packet_data["tcp_signature"] .. "\"")
    print("SYN/ACK = (" .. tostring(syn_filter) .. ", " .. tostring(ack_filter) .. ")")

    -- Construct the TCP flag string
    local tcp_flag_filter = ""
    local tcp_match_type = ""

    if syn_filter then
        tcp_flag_filter = tcp_flag_filter .. "S"
    end

    if ack_filter then
        tcp_flag_filter = tcp_flag_filter .. "A"
    end

    print("Flags string = \"" .. tcp_flag_filter .. "\"")

    -- Determine the match type for our TCP signature
    -- and process it accordingly.
    --
    -- For the moment, we'll suppose that exact matches
    -- only occur when we don0t have undefined options in our packet:

    if string.find(cur_packet_data["tcp_signature"], "*") == nil then
        tcp_match_type = "exact"
        tcp_lookup_db = osfinger_tcp_exact_list
    else
        tcp_match_type = "partial"
        tcp_lookup_db = osfinger_tcp_partial_list
    end

    -- Traverse the right fingerprint list

    -- As with NetworkMiner, if we don't get a match right away,
    -- we can round the TTL up to the next highest power of 2
    -- and then try to do another fingerprint lookup.
    --
    -- With all that said, if we still can't find a match,
    -- we call it quits and, thus, we just return nil.

    local ttl_round_check = true
    local new_tcp_sig = ""

    repeat
        for _, elem in ipairs(tcp_lookup_db) do
            for _, test_record in ipairs(elem["tests"]) do
                if elem["info"]["name"] == "EndeavourOS" then
                    --print(test_record["_attr"]["tcpsig"])
                    print(inspect(elem))
                end
                
                --[[if test_record["_attr"]["tcpsig"] == cur_packet_data["tcp_signature"]
                )then
                    print("Test record's TCP signature = " .. tostring(test_record["_attr"]["tcpsig"]))
                end]]
    
                --print("(" .. tostring(test_record["_attr"]["tcpsig"] == cur_packet_data["tcp_signature"]) .. ", " .. tostring(test_record["_attr"]["tcpflag"] == tcp_flag_filter) .. ")")
    
                if tostring(test_record["_attr"]["tcpsig"]) == cur_packet_data["tcp_signature"]
                and tostring(test_record["_attr"]["tcpflag"]) == tcp_flag_filter then
                    return elem["info"]
                end
            end
        end

        -- If we get here, we assume that we have to round up the current TTL value
        local new_ttl = cur_packet_data["ttl"]

        -- The following snippet works exactly the same in NetworkMiner
        -- (and it's, in fact, derived from the former):

        if new_ttl > 128 then
            new_ttl = 255
        elseif new_ttl > 64 then
            new_ttl = 128
        elseif new_ttl > 32 then
            new_ttl = 64
        else
            new_ttl = 32
        end

        -- Rewrite the current signature string
        cur_packet_data["ttl"] = new_ttl
        new_tcp_sig = osfinger_tcp_dissector.osfinger_build_tcp_signature(cur_packet_data)
        cur_packet_data["tcp_signature"] = new_tcp_sig

        ttl_round_check = false
    until ttl_round_check == false

    return nil
end

-- TCP Fingerprinting postdissector
function cgs_tcp_proto.dissector(buffer, pinfo, tree)
    -- Due to the info that Satori's own TCP signatures provides us,
    -- we only really ever need to process TCP packets whose SYN flag
    -- is set, which can improve performance as well as avoid overanalyzing
    -- every single packet during a live traffic capture.

    -- [TODO]: Implement a way to optimize packet dissection within TCP streams

    -- We first get address and port info so we can
    -- keep track of the same streams even if
    -- they arrive at different times:

    local ip_src = osfinger_ip_src()
    local ip_dst = osfinger_ip_dst()
    local tcp_src = osfinger_tcp_src()
    local tcp_dst = osfinger_tcp_dst()

    -- Check relevant TCP flags
    local ack_check = osfinger_tcp_ack()
    local ack_num = osfinger_tcp_ack_num()
    local fin_check = osfinger_tcp_fin()
    local syn_check = osfinger_tcp_syn()
    local urg_check = osfinger_tcp_urgent()

    -- Store other TCP/IP options
    local tcp_wsize = osfinger_tcp_wsize()
    local ip_ttl = osfinger_ip_ttl()
    local ip_df_check = osfinger_ip_df()
    local tcp_len = osfinger_tcp_len()
    local tcp_mss = osfinger_tcp_mss()
    if tcp_mss == nil then
        tcp_mss = "*"
    end

    local tcp_wscale = osfinger_tcp_wscale()
    if tcp_wscale == nil then
        tcp_wscale = "*"
    end

    local ip_hdrlen = osfinger_ip_header_len()
    local ip_id = osfinger_ip_id()
    local ip_len = osfinger_ip_length()
    local tcp_hdrlen = osfinger_tcp_header_len()

    local tcp_flags = osfinger_tcp_flags()
    local tcp_options = osfinger_tcp_options()
    local tcp_opt_array = ""
    if tcp_options ~= nil then
        tcp_opt_array = tcp_options()
    end

    --print("Options array: " .. tostring(tcp_opt_array))

    -- We're sniffing a new TCP stream or building its info,
    -- so we must find the relevant data within Satori's
    -- TCP fingerprints, which we'll later store, alongside
    -- TCP/IP addresses and ports, inside a lookup table
    -- to optimize this function as well as to improve
    -- performance by not having to search
    -- exact or partial matches every single time.

    if ip_src ~= nil and ip_dst ~= nil and tcp_src ~= nil and tcp_dst ~= nil then
        -- We also store our dissection tree for TCP
        local tcp_tree = tree:add(cgs_tcp_proto, "OS Fingerprinting through TCP")
        local tcp_os_data = nil

        if (syn_check ~= nil and syn_check.value) or (ack_check ~= nil and ack_check.value) then
            -- We first calculate the stream ID based on the current addresses and ports
            local cur_stream_id = md5.sumhexa(tostring(ip_src) .. tostring(ip_dst)) --.. tostring(tcp_src) .. tostring(tcp_dst)) -- For consistency
            local temp_tcp_sig = {}

            if osfinger.tcp_stream_table[cur_stream_id] == nil then
                -- Build a new entry in the stream table
                -- with the current address and port info:

                osfinger.tcp_stream_table[cur_stream_id] = {}
                print("New TCP stream ID detected: " .. cur_stream_id)

                osfinger.tcp_stream_table[cur_stream_id]["ip_pair"] = {
                    src_ip = tostring(ip_src),
                    dst_ip = tostring(ip_dst)
                }

                --[[osfinger.tcp_stream_table[cur_stream_id]["port_pair"] = {
                    src_port = tostring(tcp_src),
                    dst_port = tostring(tcp_dst)
                }]]--

                print(inspect(osfinger.tcp_stream_table[cur_stream_id]))

                -- After that, the next step is to build
                -- our signature (in p0f format) and compare it
                -- against the entries we have inside Satori's
                -- fingerprint database:

                -- Signature build
                --print("WSIZE: " .. tostring(tcp_wsize) .. "; MSS: " .. tostring(tcp_mss) .. "; TTL: " .. tostring(ip_ttl) .. "; WSCALE: " .. tostring(tcp_wscale))

                temp_tcp_sig = {
                    window_size = tonumber(tcp_wsize.value),
                    df_bit = ip_df_check.value,
                    syn_bit = syn_check.value or false,
                    ack_bit = ack_check.value or false,
                    ack_num = ack_num.value,
                    urg_bit = urg_check.value or false,
                    flag_array = tonumber(tcp_flags.value),
                    tcp_header_len = tonumber(tcp_hdrlen.value),
                    ip_header_len = tonumber(ip_hdrlen.value),
                    ip_id = tonumber(ip_id.value),
                    ip_length = tonumber(ip_len.value),
                    packet_len = tonumber(tcp_len.value),
                    mss = tonumber(tcp_mss.value) or "*",
                    ttl = tonumber(ip_ttl.value),
                    window_scale = tonumber(tcp_wscale.value) or "*",   -- In principle we'll only consider the exponent, not the scale itself
                    options = tcp_opt_array
                    -- Other options will be added later if they exist in the current packet
                }

                --print("Der Tafel wurde richtig konstruiert!")
                local str_sig = osfinger_tcp_dissector.osfinger_build_tcp_signature(temp_tcp_sig) -- p0fv2 format, as in Satori
                print("Current TCP Signature = \"" .. str_sig .. "\"")

                -- As our final step before writing our extracted data
                -- into the visualization tree, we must check whether
                -- our current packet data (and the signature we just computed)
                -- exists inside Satori's database or not:

                -- Add the previous signature to our packet info
                temp_tcp_sig["tcp_signature"] = str_sig

                -- Let's check what we got back
                tcp_os_data = osfinger_tcp_dissector.osfinger_tcp_match(temp_tcp_sig, osfinger_tcp_xml)
                --print(tcp_os_data ~= nil)
                if tcp_os_data ~= nil then

                    -- Store the result in the current stream record
                    osfinger.tcp_stream_table[cur_stream_id]["os_data"] = tcp_os_data
                    --print(inspect(osfinger.tcp_stream_table[cur_stream_id]["os_data"]))
                end
                -- (...)
            else
                -- If we get here, we just assume that
                -- this packet belongs to a previous stream:

                --- [TODO]: Fetch TCP signature info for the current packet ---
                local stored_stream_id = md5.sumhexa(tostring(ip_src) .. tostring(ip_dst) )--.. tostring(tcp_src) .. tostring(tcp_dst))
                if osfinger.tcp_stream_table[cur_stream_id]["os_data"] ~= nil then
                    tcp_os_data = osfinger.tcp_stream_table[cur_stream_id]["os_data"]
                    --print(inspect(tcp_os_data))
                end
                --print("[INFO]: Current packet's stream key is " .. tostring(stored_stream_id))
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

        --print("Current OS Data = " .. inspect(tcp_os_data))

        if (tcp_os_data ~= nil and tostring(tcp_os_data["name"]) ~= "") then
            packet_full_name = tcp_os_data["name"]
        end

        if (tcp_os_data ~= nil and tostring(tcp_os_data["os_name"]) ~= "") then
            packet_os_name = tcp_os_data["os_name"]
        end

        if (tcp_os_data ~= nil and tostring(tcp_os_data["os_class"]) ~= "") then
            packet_os_class = tcp_os_data["os_class"]
        end

        if (tcp_os_data ~= nil and tostring(tcp_os_data["os_vendor"]) ~= "") then
            packet_os_vendor = tcp_os_data["os_vendor"]
        end

        if (tcp_os_data ~= nil and tostring(tcp_os_data["device_type"]) ~= "") then
            packet_device_type = tcp_os_data["device_type"]
        end

        if (tcp_os_data ~= nil and tostring(tcp_os_data["device_vendor"]) ~= "") then
            packet_device_vendor = tcp_os_data["device_vendor"]
        end

        --print("Current Info: (" .. packet_full_name .. " (" .. packet_os_name .. "), " .. packet_os_class .. "; " .. packet_os_vendor .. "; " .. packet_device_type .. " (by " .. packet_device_vendor .. "))")

        tcp_tree:add(osfinger_tcp_full_name_F, packet_full_name)
        tcp_tree:add(osfinger_tcp_os_name_F, packet_os_name)
        tcp_tree:add(osfinger_tcp_os_class_F, packet_os_class)
        tcp_tree:add(osfinger_tcp_os_vendor_F, packet_os_vendor)
        tcp_tree:add(osfinger_tcp_device_type_F, packet_device_type)
        tcp_tree:add(osfinger_tcp_device_vendor_F, packet_device_vendor)
    end

    osfinger_tcp_dissector.tcp_stream_table = osfinger.tcp_stream_table
end

-- We add this "protocol" as a postdissector
register_postdissector(cgs_tcp_proto)

--local tcp_port_table = DissectorTable.get("tcp.port")
--tcp_port_table:add("0-65535", cgs_tcp_proto)

return osfinger_tcp_dissector
--local inspect = require("inspect")
--print(inspect(osfinger.tcp_stream_table))
