module(..., package.seeall)

local packet = require("core.packet")
local bit = require("bit")
local ffi = require("ffi")

local C = ffi.C
local receive, transmit = link.receive, link.transmit
local cast = ffi.cast

Tagger = {}
Untagger = {}

-- 802.1q
local dotq_tpid = 0x8100
local o_ethernet_ethertype = 12
local uint32_ptr_t = ffi.typeof('uint32_t*')


-- build a VLAN tag consisting of 2 bytes of TPID set to 0x8100 followed by the
-- TCI field which in turns consists of PCP, DEI and VID (VLAN id). Both PCP
-- and DEI is always 0
local function build_tag(vid)
   return ffi.C.htonl(bit.bor(bit.lshift(dotq_tpid, 16), vid))
end

-- pop a VLAN tag (4 byte of TPID and TCI) from a packet
function pop_tag(pkt)
   local payload = pkt.data + o_ethernet_ethertype
   local length = pkt.length
   pkt.length = length - 4
   C.memmove(payload, payload + 4, length - o_ethernet_ethertype - 4)
end

-- push a VLAN tag onto a packet
function push_tag(pkt, tag)
   local payload = pkt.data + o_ethernet_ethertype
   local length = pkt.length
   pkt.length = length + 4
   C.memmove(payload + 4, payload, length - o_ethernet_ethertype)
   cast(uint32_ptr_t, payload)[0] = tag
end

-- extract TCI (2 bytes) from packet, no check is performed to verify that the
-- packet is carrying a VLAN tag, if it's an untagged frame these bytes will be
-- Ethernet payload
function extract_tci(pkt)
   return ffi.C.ntohs(ffi.cast("uint16_t*", packet.data(pkt) + o_ethernet_ethertype + 2)[0])
end

-- extract VLAN id from TCI
function tci_to_vid(tci)
   return bit.band(tci, 0xFFF)
end


function Tagger:new(conf)
   local o = setmetatable({}, {__index=Tagger})
   o.tag = build_tag(assert(conf.tag))
   return o
end

function Tagger:push ()
   local input, output = self.input.input, self.output.output
   local tag = self.tag
   for _=1,link.nreadable(input) do
      local pkt = receive(input)
      push_tag(pkt, tag)
      transmit(output, pkt)
   end
end

function Untagger:new(conf)
   local o = setmetatable({}, {__index=Untagger})
   o.tag = build_tag(assert(conf.tag))
   return o
end

function Untagger:push ()
   local input, output = self.input.input, self.output.output
   local tag = self.tag
   for _=1,link.nreadable(input) do
      local pkt = receive(input)
      local payload = pkt.data + o_ethernet_ethertype
      if cast(uint32_ptr_t, payload)[0] ~= tag then
         -- Incorrect VLAN tag; drop.
         packet.free(pkt)
      else
         pop_tag(pkt)
         transmit(output, pkt)
      end
   end
end


VlanMux = {}
function VlanMux:new(conf)
   local self = setmetatable({}, {__index=VlanMux})
   self.ethertype_8100 = ffi.cast("uint16_t", 0x0081) -- 0x8100 in network byte order
   return self
end

function VlanMux:push()
   local noutputs = #self.output
   if noutputs > 0 then
      for name, l in pairs(self.input) do
         local maxoutput = link.max
         -- find out max number of packets we can put out an interface
         -- this is kind of bad because we limit ourselves by the interface with
         -- the fullest queue, yet packets might go out a different interface. We
         -- don't know until we've looked in the packet and parsed the VLAN id. I
         -- suppose we kind of get some HOLB with this :(
         for _, o in ipairs(self.output) do
            maxoutput = math.min(maxoutput, link.nwritable(o))
         end

         if type(name) == "string" then
            for _ = 1, math.min(link.nreadable(l), maxoutput) do
               local p = receive(l)
               local ethertype = ffi.cast("uint16_t*", packet.data(p) + o_ethernet_ethertype)[0]

               if name == "trunk" then -- trunk
                  -- check for ethertype 0x8100 (802.1q VLAN tag)
                  if ethertype == self.ethertype_8100 then
                     -- dig out TCI field
                     local tci = extract_tci(p)
                     local vid = tci_to_vid(tci)
                     local oif = self.output["vlan"..vid]
                     pop_tag(p)
                     self:transmit(oif, p)

                  else -- untagged, send to native output
                     self:transmit(self.output.native, p)
                  end
               elseif name == "native" then
                  self:transmit(self.output.trunk, p)
               else -- some vlanX interface
                  local vid = tonumber(string.sub(name, 5))
                  push_tag(p, build_tag(vid))
                  self:transmit(self.output.trunk, p)
               end
            end
         end
      end
   end
end

-- transmit packet out interface if given interface exists, otherwise drop
function VlanMux:transmit(o, pkt)
   if o == nil then
      packet.free(pkt)
   else
      transmit(o, pkt)
   end
end


function selftest()
   local app = require("core.app")
   local basic_apps = require("apps.basic.basic_apps")

   local c = config.new()
   config.app(c, "source", basic_apps.Source)
   config.app(c, "vlan_mux", VlanMux)
   config.app(c, "sink", basic_apps.Sink)

   config.link(c, "source.output -> vlan_mux.vlan1")
   config.link(c, "vlan_mux.trunk -> sink.input")
   app.configure(c)
   app.main({duration = 1})

   print("source sent: " .. link.stats(app.app_table.source.output.output).txpackets)
   print("sink received: " .. link.stats(app.app_table.sink.input.input).rxpackets)
end
