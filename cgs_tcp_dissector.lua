----------------------------------------
-- script-name: cgs_tcp_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023, Carlos González Sanz
--
----------------------------------------

local inspect = require("inspect")

-- Plugin constants/global variables
CGS_OS_TCP_PROTO = CGS_OS_PROTO .. "-tcp"
CGS_OS_TCP_STREAM_PREFIX = "osf_tcp_stream_"

-- Fingerprinting protocol for TCP
local cgs_tcp_proto = Proto(CGS_OS_TCP_PROTO, "OS Fingerprinting through TCP")

--- Fields for this TCP postdissector ---
-- TCP/IP adresses and ports (in part to build a lookup table)
local osf_ip_src = Field.new("ip.src")
local osf_ip_dst = Field.new("ip.dst")
local osf_tcp_src = Field.new("tcp.srcport")
local osf_tcp_dst = Field.new("tcp.dstport")

-- More specific TCP parameters
local osf_tcp_wsize = Field.new("tcp.window_size")

-- Judging by Satori's own signatures, only the
-- SYN and ACK flags are ever taken into account:

local osf_tcp_ack = Field.new("tcp.flags.ack")
local osf_tcp_syn = Field.new("tcp.flags.syn")
local osf_tcp_fin = Field.new("tcp.flags.fin")  -- To free entries from the lookup table whenever we're sure that a given TCP connection has ended

local osf_tcp_options = Field.new("tcp.options")

-- Extra field to store a TCP stream lookup table
local cgs_tcp_stream_id = 0 -- By default for each capture session/reload
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
local osf_tcp_xml = preloadXML(OSF_SATORI_TCP)

-- Function that searches for existing address/port pairs
-- inside our lookup table

function osf_tcp_lookup_search(src_addr, dst_addr, src_tcpport, dst_tcpport)
    -- Simple linear search for now --
    for _, stream_data in pairs(cgs_tcp_stream_table) do
        -- Extracting it exactly as we specified earlier
        local src_ip = stream_data["ip_pair"]["src_ip"]
        local dst_ip = stream_data["ip_pair"]["dst_ip"]
        local src_port = stream_data["port_pair"]["src_port"]
        local dst_port = stream_data["port_pair"]["dst_port"]

        if (src_addr == src_ip)
        and (dst_addr == dst_ip)
        and (src_port == src_tcpport)
        and (dst_port == dst_tcpport) then
            return true
        end
    end

    return false
end

-- Very similar to the previous function except it returns the stream index/key
-- Mostly for debugging --
function osf_tcp_lookup_index_search(src_addr, dst_addr, src_tcpport, dst_tcpport)
    -- Simple linear search for now --
    for stream_index, stream_data in pairs(cgs_tcp_stream_table) do
        -- Extracting it exactly as we specified earlier
        local src_ip = stream_data["ip_pair"]["src_ip"]
        local dst_ip = stream_data["ip_pair"]["dst_ip"]
        local src_port = stream_data["port_pair"]["src_port"]
        local dst_port = stream_data["port_pair"]["dst_port"]

        if (src_addr == src_ip)
        and (dst_addr == dst_ip)
        and (src_port == src_tcpport)
        and (dst_port == dst_tcpport) then
            return stream_index
        end
    end

    return nil
end

-- Function that allows us to build p0f TCP signatures
-- based on the captured data (to compare it later against
-- Satori's TCP fingerprint database):

function osf_build_tcp_signature(packet_data)
    -- (...)

    -- return (current TCP signature with p0f's format regarding TCP options)
end

-- Function that tries to find a signature match between
-- the current frame and all TCP signatures:

function is_osf_tcp_match(cur_packet_data, cur_sig, finger_db)
    -- (...)

    -- return (composite_sig in finger_db)
end

-- TCP Fingerprinting postdissector
function cgs_tcp_proto.dissector(buffer,pinfo,tree)
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
    local fin_check = osf_tcp_fin()
    local syn_check = osf_tcp_syn()

    -- We store also our dissection tree for TCP
    local tcp_tree = tree:add(cgs_tcp_proto, "OS FIngerprinting through TCP")

    if syn_check ~= nil and syn_check.value then   --- Always checked first for obvious reasons ---
        -- We're sniffing a new TCP stream (or building its info),
        -- so we must find the relevant data within Satori's
        -- TCP fingerprints, which we'll later store, alongside
        -- TCP/IP addresses and ports, inside a lookup table
        -- to optimize this function as well as to improve
        -- performance by not having to search
        -- exact or partial matches every single time.

        -- We first create an empty entry in the lookup table
        local cur_stream_id = CGS_OS_TCP_STREAM_PREFIX .. tostring(cgs_tcp_stream_id)

        if not osf_tcp_lookup_search(tostring(ip_src), tostring(ip_dst), tostring(tcp_src), tostring(tcp_dst)) then
            cgs_tcp_stream_table[cur_stream_id] = {}

            -- Let's put in address and port info
            cgs_tcp_stream_table[cur_stream_id]["ip_pair"] = {
                src_ip = tostring(ip_src),
                dst_ip = tostring(ip_dst)
            }

            cgs_tcp_stream_table[cur_stream_id]["port_pair"] = {
                src_port = tostring(tcp_src),
                dst_port = tostring(tcp_dst)
            }

            -- Move to the next available spot
            cgs_tcp_stream_id = cgs_tcp_stream_id + 1
            print(inspect(cgs_tcp_stream_table))
            print("Number of distinct registered stream IDs (directed edges) for this session = " .. tostring(cgs_tcp_stream_id))
        end

        -- (...)
    elseif (ack_check ~= nil and syn_check ~= nil) and (ack_check.value and not syn_check.value) then
        -- If we get here, we just assume that
        -- this packet belongs to a previous
        -- stream. The exact stream this belongs
        -- to will be deduced both from the info
        -- contained within this session's
        -- lookup table and the pairs of TCP/IP
        -- addresses and ports of the current frame/packet.

        --print("ACK activated")

        local packet_index = osf_tcp_lookup_index_search(tostring(ip_src), tostring(ip_dst), tostring(tcp_src), tostring(tcp_dst))
        print("[INFO]: Current packet belongs to " .. packet_index)

        -- (...)
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


--local inspect = require("inspect")
--print(inspect(cgs_tcp_stream_table))
