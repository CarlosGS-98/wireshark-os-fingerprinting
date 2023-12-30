----------------------------------------
-- script-name: cgs_tcp_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023, Carlos González Sanz
--
----------------------------------------

local osf = require("osf_utils")
local inspect = require("inspect")
local md5 = require("md5")

local osf_tcp_dissector = {}

-- Plugin constants/global variables
CGS_OS_TCP_PROTO = CGS_OS_PROTO .. "-tcp"

-- Fingerprinting protocol for TCP
local cgs_tcp_proto = Proto(CGS_OS_TCP_PROTO, "OS Fingerprinting - TCP")

--- Fields for this TCP postdissector ---
-- TCP/IP adresses and ports (in part to build a lookup table)
local osf_ip_src = Field.new("ip.src")
local osf_ip_dst = Field.new("ip.dst")
local osf_tcp_src = Field.new("tcp.srcport")
local osf_tcp_dst = Field.new("tcp.dstport")

-- More specific TCP parameters
local osf_tcp_wsize = Field.new("tcp.window_size")
local osf_tcp_mss = Field.new("tcp.options.mss_val")
local osf_ip_ttl = Field.new("ip.ttl")
local osf_tcp_wscale = Field.new("tcp.options.wscale.shift")
local osf_ip_df = Field.new("ip.flags.df")
local osf_tcp_len = Field.new("tcp.len")

-- Judging by Satori's own signatures, only the
-- SYN and ACK flags are ever taken into account:

local osf_tcp_ack = Field.new("tcp.flags.ack")
local osf_tcp_ack_num = Field.new("tcp.ack")
local osf_tcp_syn = Field.new("tcp.flags.syn")
local osf_tcp_fin = Field.new("tcp.flags.fin")      -- To free entries from the lookup table whenever we're sure that a given TCP connection has ended
local osf_tcp_urgent = Field.new("tcp.flags.urg")
local osf_tcp_flags = Field.new("tcp.flags")        -- To detect packet anomalies

local osf_tcp_options = Field.new("tcp.options")

-- Header parameters
local osf_ip_header_len = Field.new("ip.hdr_len")
local osf_ip_id = Field.new("ip.id")
local osf_ip_length = Field.new("ip.len")
local osf_tcp_header_len = Field.new("tcp.hdr_len")

-- Extra field to store a TCP stream lookup table
local cgs_tcp_stream_table = {
    --[[
        Each entry in this table will have the following format:

        stream_string_id = {
            ip_pair = {src_ip = SRC_IP, dst_ip = DST_IP},
            port_pair = {src_port = SRC_PORT, dst_port = DST_PORT},
            osf_data = {
                -- This is mainly to hold all the different values we store inside our protocol during a live/offline capture --
                stream_osf_name = CGS_OS_TCP_PROTO.os_name,
                stream_osf_class = CGS_OS_TCP_PROTO.os_class,
                stream_osf_devname = CGS_OS_TCP_PROTO.device_name,
                stream_osf_devtype = CGS_OS_TCP_PROTO.device_type,
                stream_osf_devvendor = CGS_OS_TCP_PROTO.device_vendor,
                (...)
            }
        }, (...)
    ]]--
}

-- Create the fields for our "protocol"
local osf_tcp_os_name_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".os_name", "OS Name")                                                  -- "name" (instead of "os_name", since it's empty most of the time)
local osf_tcp_os_class_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".os_class", "OS Class", "The OS family that this system belongs to")  -- "os_class"
local osf_tcp_device_name_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".device_name", "Device", "Device that runs this OS")               -- "device_name"
local osf_tcp_device_type_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".device_type", "Device Type", "Device type/class")                 -- "device_type"
local osf_tcp_device_vendor_F = ProtoField.string(CGS_OS_TCP_PROTO .. ".device_vendor", "Device Vendor")                                -- "device_vendor"
-- (...)

-- Add fields to the pseudo-protocol
cgs_tcp_proto.fields = {osf_tcp_os_name_F, osf_tcp_os_class_F, osf_tcp_device_name_F, osf_tcp_device_type_F, osf_tcp_device_vendor_F}

-- Preload Satori's TCP signatures
local osf_tcp_xml = osf.preloadXML(OSF_SATORI_TCP)

-- Function that allows us to build p0f TCP signatures
-- based on the captured data (to compare it later against
-- Satori's TCP fingerprint database):

function osf_tcp_dissector.osf_build_tcp_signature(packet_data)
    -- We'll store some of the info contained inside packet_data
    -- inside a new anonymous table so we can later concatenate its contents
    -- (ideally with ":" as the separator).
    --
    -- Additionally, we'll use two additional tables to create the
    -- whole TCP signature (in p0fv2 format):
    -- one for storing TCP options and another one for TCP quirks.

    -- Temporary table to hold the first part of our signature:
    -- (FORMAT): "window_size:ttl:df_bit:total_header_length"
    print("Options table = " .. tostring(packet_data["options"]))

    local tcp_sig_first = table.concat({
        tostring(packet_data["window_size"]),
        tostring(packet_data["ttl"]),
        tostring(packet_data["df_bit"] and 1 or 0),
        tostring(tonumber(packet_data["ip_header_len"]) + tonumber(packet_data["tcp_header_len"]))
    }, ":")

    print("First part = " .. tcp_sig_first)

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

                tcp_timestamp_echo = tonumber(packet_data["options"]:uint(option_index, 4))
                tcp_timestamp_reply = tonumber(packet_data["options"]:uint(option_index + 4, 4))

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

    print("Second part = " .. tcp_sig_first .. tcp_sig_second)

    -- The third and last part of our signature
    -- will consist of quirks that the current packet
    -- presents, if there are any present:

    local tcp_sig_third = ""

    -- Heavily based off https://github.com/xnih/satori/blob/master/satoriTCP.py --
    if (packet_data["options"] ~= "") and (tonumber(packet_data["options"]:get_index(packet_data["options"]:len() - 1)) == 0) then
        tcp_sig_third = tcp_sig_third .. "P"
    end
    print("P-Check tested")

    if packet_data["ip_id"] == 0 then
        tcp_sig_third = tcp_sig_third .. "Z"
    end
    print("Z-Check tested")

    if packet_data["ip_header_len"] > 20 then
        tcp_sig_third = tcp_sig_third .. "I"
    end
    print("I-Check tested")

    if (packet_data["ip_length"] - packet_data["ip_header_len"] - packet_data["tcp_header_len"]) ~= 0 then
        tcp_sig_third = tcp_sig_third .. "D"
    end
    print("D-Check tested")

    if packet_data["urg_bit"] then
        tcp_sig_third = tcp_sig_third .. "U"
    end
    print("U-Check tested")

    if (packet_data["syn_check"] or (packet_data["syn_check"] and packet_data["ack_check"])) and (packet_data["ack_num"] ~= 0) then
        tcp_sig_third = tcp_sig_third .. "A"
    end
    print("A-Check tested")

    if tcp_timestamp_reply ~= nil and tcp_timestamp_echo ~= nil then
        local timestamp_delta = tcp_timestamp_reply - tcp_timestamp_echo

        if (packet_data["syn_flag"] and timestamp_delta ~= 0) or (packet_data["syn_flag"] and packet_data["ack_flag"] and tcp_timestamp_echo ~= nil and tcp_timestamp_reply ~= nil) then
            tcp_sig_third = tcp_sig_third .. "T"
        end
    end
   
    print("T-Check tested")

    -- Lua doesn't support bitwise operators until Lua 5.3
    if (bit32.band(packet_data["flag_array"], 0xFFED)) ~= 0 then  -- SYN+ACK = 0x12 = 18
        tcp_sig_third = tcp_sig_third .. "F"
    end
    print("F-Check tested")

    if tcp_sig_third == "" then
        tcp_sig_third = "."
    end
    print(".-Check tested")

    print("Third part = " .. tcp_sig_first .. tcp_sig_second .. tcp_sig_third)

    return tcp_sig_first .. tcp_sig_second .. tcp_sig_third
end

-- Function that tries to find a signature match between
-- the current frame and all TCP signatures:

function osf_tcp_dissector.is_osf_tcp_match(cur_packet_data, cur_sig, finger_db)
    -- (...)

    -- return (composite_sig in finger_db)
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

    local ip_src = osf_ip_src()
    local ip_dst = osf_ip_dst()
    local tcp_src = osf_tcp_src()
    local tcp_dst = osf_tcp_dst()

    -- Check relevant TCP flags
    local ack_check = osf_tcp_ack()
    local ack_num = osf_tcp_ack_num()
    local fin_check = osf_tcp_fin()
    local syn_check = osf_tcp_syn()
    local urg_check = osf_tcp_urgent()

    -- Store other TCP/IP options
    local tcp_wsize = osf_tcp_wsize()
    local ip_ttl = osf_ip_ttl()
    local ip_df_check = osf_ip_df()
    local tcp_len = osf_tcp_len()
    local tcp_mss = osf_tcp_mss()
    if tcp_mss == nil then
        tcp_mss = "*"
    end

    local tcp_wscale = osf_tcp_wscale()
    if tcp_wscale == nil then
        tcp_wscale = "*"
    end

    local ip_hdrlen = osf_ip_header_len()
    local ip_id = osf_ip_id()
    local ip_len = osf_ip_length()
    local tcp_hdrlen = osf_tcp_header_len()

    local tcp_flags = osf_tcp_flags()
    local tcp_options = osf_tcp_options()
    local tcp_opt_array = ""
    if tcp_options ~= nil then
        tcp_opt_array = tcp_options()
    end

    print("Options array: " .. tostring(tcp_opt_array))

    -- We also store our dissection tree for TCP
    local tcp_tree = tree:add(cgs_tcp_proto, "OS FIngerprinting through TCP")

    -- We're sniffing a new TCP stream or building its info,
    -- so we must find the relevant data within Satori's
    -- TCP fingerprints, which we'll later store, alongside
    -- TCP/IP addresses and ports, inside a lookup table
    -- to optimize this function as well as to improve
    -- performance by not having to search
    -- exact or partial matches every single time.

    if ip_src ~= nil and ip_dst ~= nil and tcp_src ~= nil and tcp_dst ~= nil then
        if (syn_check ~= nil and syn_check.value) or (ack_check ~= nil and ack_check.value) then
            -- We first calculate the stream ID based on the current addresses and ports
            local cur_stream_id = md5.sumhexa(tostring(ip_src) .. tostring(tcp_src) .. tostring(ip_dst) .. tostring(tcp_dst)) -- For consistency
            local temp_tcp_sig = {}

            if cgs_tcp_stream_table[cur_stream_id] == nil then
                -- Build a new entry in the stream table
                -- with the current address and port info:

                cgs_tcp_stream_table[cur_stream_id] = {}
                print("New stream ID detected: " .. cur_stream_id)

                cgs_tcp_stream_table[cur_stream_id]["ip_pair"] = {
                    src_ip = tostring(ip_src),
                    dst_ip = tostring(ip_dst)
                }

                cgs_tcp_stream_table[cur_stream_id]["port_pair"] = {
                    src_port = tostring(tcp_src),
                    dst_port = tostring(tcp_dst)
                }

                print(inspect(cgs_tcp_stream_table[cur_stream_id]))

                -- After that, the next step is to build
                -- our signature (in p0f format) and compare it
                -- against the entries we have inside Satori's
                -- fingerprint database:

                -- Signature build
                print("WSIZE: " .. tostring(tcp_wsize) .. "; MSS: " .. tostring(tcp_mss) .. "; TTL: " .. tostring(ip_ttl) .. "; WSCALE: " .. tostring(tcp_wscale))

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

                print("Der Tafel wurde richtig konstruiert!")
                local str_sig = osf_tcp_dissector.osf_build_tcp_signature(temp_tcp_sig) -- p0fv2 format, as in Satori
                print("Current TCP Signature = \"" .. str_sig .. "\"")
            else
                -- If we get here, we just assume that
                -- this packet belongs to a previous stream:

                --- [TODO]: Fetch TCP signature info for the current packet ---
                local stored_stream_id = md5.sumhexa(tostring(ip_src) .. tostring(tcp_src) .. tostring(ip_dst) .. tostring(tcp_dst))
                print("[INFO]: Current packet's stream key is " .. tostring(stored_stream_id))
            end
        end
    end

    -- After all those checks, we finally display
    -- all the relevant info from our current packet:

    --tcp_tree:add(osf_tcp_os_name_F, src)
    --tcp_tree:add(osf_tcp_os_class_F, src)
    --tcp_tree:add(osf_tcp_device_name_F, src)
    --tcp_tree:add(osf_tcp_device_type_F, src)
    --tcp_tree:add(osf_tcp_device_vendor_F, src)
end

-- We add this "protocol" as a postdissector
register_postdissector(cgs_tcp_proto)

return osf_tcp_dissector
--local inspect = require("inspect")
--print(inspect(cgs_tcp_stream_table))
