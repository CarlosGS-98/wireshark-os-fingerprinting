----------------------------------------
-- script-name: cgs_dummy_dissector.lua
--
-- author: Carlos González Sanz <mail pending>
-- Copyleft (ɔ) 2023, Carlos González Sanz
--
----------------------------------------

-- Constantes del plugin
CGS_DUMMY_PROTO_NAME = "tcp-os-fingerprinter"

-- Campos del postdisector de juguete
local ip_src_f = Field.new("ip.src")
local ip_dst_f = Field.new("ip.dst")
local tcp_src_f = Field.new("tcp.srcport")
local tcp_dst_f = Field.new("tcp.dstport")

-- Protocolo de juguete para probar
-- la disección de paquetes TCP en Wireshark
local cgs_dummy_proto = Proto(CGS_DUMMY_PROTO_NAME, "OS Fingerprinting through TCP")

-- create the fields for our "protocol"
local src_F = ProtoField.string(CGS_DUMMY_PROTO_NAME + "src", "Source")
local dst_F = ProtoField.string(CGS_DUMMY_PROTO_NAME + "trivial.dst", "Destination")
local conv_F = ProtoField.string(CGS_DUMMY_PROTO_NAME + "trivial.conv", "Conversation","A Conversation")

-- add the field to the protocol
cgs_dummy_proto.fields = {src_F, dst_F, conv_F}

-- create a function to "postdissect" each frame
function cgs_dummy_proto.dissector(buffer,pinfo,tree)
    -- obtain the current values the protocol fields
    local tcp_src = tcp_src_f()
    local tcp_dst = tcp_dst_f()
    local ip_src = ip_src_f()
    local ip_dst = ip_dst_f()

    if tcp_src then
        local subtree = tree:add(cgs_dummy_proto,"Trivial Protocol Data")
        local src = tostring(ip_src) .. ":" .. tostring(tcp_src)
        local dst = tostring(ip_dst) .. ":" .. tostring(tcp_dst)

        local conv = src  .. "->" .. dst
        subtree:add(src_F, src)
        subtree:add(dst_F, dst)
        subtree:add(conv_F, conv)
    end
end

-- register our protocol as a postdissector
register_postdissector(cgs_dummy_proto)
