----------------------------------------
-- script-name: cgs_smb_dissector.lua
--
-- author: Carlos González Sanz <cgonzalezsanz98@gmail.com>
-- Copyleft (ɔ) 2023, Carlos González Sanz
--
----------------------------------------

local osfinger = require("osfinger_utils")
local inspect = require("inspect")
local md5 = require("md5")

local osfinger_smb_dissector = {}

-- Plugin constants/global variables
CGS_OS_SMB_PROTO = CGS_OS_PROTO .. "-smb"
SMB_NO_NAME = "NONE"

-- Fingerprinting protocol for TCP
local cgs_smb_proto = Proto(CGS_OS_SMB_PROTO, "OS Fingerprinting - SMB")

--- Fields for this DNS postdissector ---
local osfinger_smb_id = Field.new("dns.id")
local osfinger_smb_query_name = Field.new("dns.qry.name")
local osfinger_smb_response_name = Field.new("dns.resp.name")

-- Fields for the DNS dissection tree
local osfinger_smb_full_name_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".full_name", "Device/OS Full Name", "Can include version info about the given OS if it's one")  
local osfinger_smb_os_name_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".os_name", "OS Name")                                                      -- "name" (instead of "os_name", since it's empty most of the time)
local osfinger_smb_os_class_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".os_class", "OS Class", "The OS family that this system belongs to")      -- "os_class"
local osfinger_smb_os_vendor_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".os_vendor", "OS Vendor", "The OS vendor/distributor of this system")    -- "os_vendot"                   -- "device_name"
local osfinger_smb_device_type_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".device_type", "Device Type", "Device type/class")                     -- "device_type"
local osfinger_smb_device_vendor_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".device_vendor", "Device Vendor")
local osfinger_smb_record_tree_F = ProtoField.string(CGS_OS_SMB_PROTO .. ".record", "Current Match")

-- Add fields to the pseudo-protocol
cgs_smb_proto.fields = {osfinger_smb_full_name_F, osfinger_smb_os_name_F, osfinger_smb_os_class_F, osfinger_smb_os_vendor_F, osfinger_smb_device_type_F, osfinger_smb_device_vendor_F, osfinger_smb_record_tree_F}

-- Base TCP/IP adresses and ports (in part to build a lookup table)
local osfinger_ip_src = Field.new("ip.src")
local osfinger_ip_dst = Field.new("ip.dst")
local osfinger_tcp_src = Field.new("tcp.srcport")
local osfinger_tcp_dst = Field.new("tcp.dstport")
local osfinger_udp_src = Field.new("udp.srcport")
local osfinger_udp_dst = Field.new("udp.dstport")

--- Flag fields for this DNS postdissector ---
local osfinger_smb_flags = Field.new("dns.flags")    -- We expect this to be a byte array (maybe)

-- Preload Satori's DNS signatures
local osfinger_smb_xml = osfinger.preloadXML(OSFINGER_SATORI_SMB)["SMB"]
local osfinger_smb_exact_list, osfinger_smb_partial_list = osfinger.signature_partition(osfinger_smb_xml, "SMB", "smb_tests")

--- Fields for this SMB postdissector ---
-- (WIP) --

--- Extra functions for this SMB postdissector ---
-- (WIP) --

function cgs_smb_proto.dissector(buffer, pinfo, tree)
    -- (WIP) --
end
