----------------------------------------
-- script-name: cgs_nt_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023, Carlos González Sanz
--
----------------------------------------

local osfinger = require("osfinger_utils")
local inspect = require("inspect")
local md5 = require("md5")

local osfinger_ntp_dissector = {}

-- Plugin constants/global variables
CGS_OS_NTP_PROTO = CGS_OS_PROTO .. "-ntp"
NTP_NO_NAME = "NONE"

-- Fingerprinting protocol for TCP
local cgs_ntp_proto = Proto(CGS_OS_NTP_PROTO, "OS Fingerprinting - NTP")

--- Fields for this DNS postdissector ---
local osfinger_ntp_id = Field.new("dns.id")
local osfinger_ntp_query_name = Field.new("dns.qry.name")
local osfinger_ntp_response_name = Field.new("dns.resp.name")

-- Fields for the DNS dissection tree
local osfinger_ntp_full_name_F = ProtoField.string(CGS_OS_NTP_PROTO .. ".full_name", "Device/OS Full Name", "Can include version info about the given OS if it's one")  
local osfinger_ntp_os_name_F = ProtoField.string(CGS_OS_NTP_PROTO .. ".os_name", "OS Name")                                                      -- "name" (instead of "os_name", since it's empty most of the time)
local osfinger_ntp_os_class_F = ProtoField.string(CGS_OS_NTP_PROTO .. ".os_class", "OS Class", "The OS family that this system belongs to")      -- "os_class"
local osfinger_ntp_os_vendor_F = ProtoField.string(CGS_OS_NTP_PROTO .. ".os_vendor", "OS Vendor", "The OS vendor/distributor of this system")    -- "os_vendot"                   -- "device_name"
local osfinger_ntp_device_type_F = ProtoField.string(CGS_OS_NTP_PROTO .. ".device_type", "Device Type", "Device type/class")                     -- "device_type"
local osfinger_ntp_device_vendor_F = ProtoField.string(CGS_OS_NTP_PROTO .. ".device_vendor", "Device Vendor")

-- Add fields to the pseudo-protocol
cgs_ntp_proto.fields = {osfinger_ntp_full_name_F, osfinger_ntp_os_name_F, osfinger_ntp_os_class_F, osfinger_ntp_os_vendor_F, osfinger_ntp_device_type_F, osfinger_ntp_device_vendor_F, osfinger_ntp_record_tree_F}

-- Base TCP/IP adresses and ports (in part to build a lookup table)
local osfinger_ip_src = Field.new("ip.src")
local osfinger_ip_dst = Field.new("ip.dst")
local osfinger_tcp_src = Field.new("tcp.srcport")
local osfinger_tcp_dst = Field.new("tcp.dstport")
local osfinger_udp_src = Field.new("udp.srcport")
local osfinger_udp_dst = Field.new("udp.dstport")

--- Flag fields for this DNS postdissector ---
local osfinger_ntp_flags = Field.new("dns.flags")    -- We expect this to be a byte array (maybe)

-- Preload Satori's DNS signatures
local osfinger_ntp_xml = osfinger.preloadXML(OSFINGER_SATORI_NTP)["NTP"]
local osfinger_ntp_exact_list, osfinger_ntp_partial_list = osfinger.signature_partition(osfinger_ntp_xml, "NTP", "ntp_tests")

--- Fields for this NTP postdissector ---
-- (WIP) --

--- Extra functions for this NTP postdissector ---
-- (WIP) --

function cgs_ntp_proto.dissector(buffer, pinfo, tree)
    -- (WIP) --
end
