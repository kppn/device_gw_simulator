#!/bin/env ruby

require 'pp'
require 'json'
require 'base64'
require 'rubygems'
require 'pcaprub'
require_relative 'lib/lora/protocol'
require_relative 'lib/packet_forwarder/protocol'



appkey = ["74ADCDC988A9B513F2A03FB9C39CE781"].pack('H*')
appskey = ["74ADCDC988A9B513F2A03FB9C39CE781"].pack('H*')
nwkskey = ["47E3C9151666263D07C34311696FE772"].pack('H*')

if_name = 'ens3'


#==================================================================
capture = PCAPRUB::Pcap.open_live(if_name, 65535, true, 0)
capture.setfilter('udp port 1700')

loop do
  puts(capture.stats())
  pkt = capture.next()

  if pkt
    puts "captured packet" 
    udp_payload = pkt[42..-1]

    pf = PacketForwarder.from_bytes(udp_payload)
    if pf.payload && pf.payload['rxpk']
      pp pf
      puts ""

      pf.payload['rxpk'].each do |rxpk|
        lora_bytes = Base64.decode64(rxpk['data'])
        phypayload = PHYPayload.from_bytes(lora_bytes, appkey: appkey, nwkskey: nwkskey, appskey: appskey)

        pp phypayload
        puts ""
      end
    elsif pf.payload && pf.payload['txpk']
        txpk = pf.payload['txpk']
        lora_bytes = Base64.decode64(txpk['data'])
        phypayload = PHYPayload.from_bytes(lora_bytes, appkey: appkey, nwkskey: nwkskey, appskey: appskey)

        pp phypayload
        puts ""
    else
      pp pf
      puts ""
    end
  end

  puts ""

  sleep(1)
end


lora_enc = Base64.decode64("YCoUBCYAAgABzsoSL6s=")

pp "lora raw value: #{lora_enc.to_hexstr}"
puts

phypayload = PHYPayload.from_bytes(lora_enc, appskey, :down)
pp phypayload

puts
pp "raw value: #{phypayload.macpayload.frmpayload.value.to_hexstr}"



