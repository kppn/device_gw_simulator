#!/bin/env ruby

require 'pp'
require 'json'
require 'base64'
require 'rubygems'
require 'pcaprub'
require_relative 'lib/lora/protocol'



appskey = ["194730F1F3CCD64DDB0E271F247EBA41"].pack('H*')
nwkskey = ["7001D7176C75A948B3B08B1D99DA1E49"].pack('H*')

if_name = 'br0'


capture = PCAPRUB::Pcap.open_live(if_name, 65535, true, 0)
capture.setfilter('udp port 1700')

loop do
  puts(capture.stats())
  pkt = capture.next()
  if pkt
    puts "captured packet" 
    udp_payload = pkt[42..-1]

    pp udp_payload[0].unpack('C*')[0]
    json_raw  = case udp_payload[3].unpack('C*')[0]
                when 0
		  udp_payload[12..-1]
                when 3
		  udp_payload[4..-1]
		else
		  nil
		end
    if json_raw
      json = JSON.parse(json_raw)
    end
  end
  sleep(1)
end


lora_enc = Base64.decode64("YCoUBCYAAgABzsoSL6s=")

pp "lora raw value: #{lora_enc.to_hexstr}"
puts

phypayload = PHYPayload.from_bytes(lora_enc, appskey, :down)
pp phypayload

puts
pp "raw value: #{phypayload.macpayload.frmpayload.value.to_hexstr}"



