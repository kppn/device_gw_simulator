#!/bin/env ruby

require 'pp'
require 'json'
require 'base64'
require 'rubygems'
require 'pcaprub'
require_relative 'lib/lora/protocol'



appskey = ["194730F1F3CCD64DDB0E271F247EBA41"].pack('H*')
nwkskey = ["7001D7176C75A948B3B08B1D99DA1E49"].pack('H*')

lora_enc = Base64.decode64("YCoUBCYAAgABzsoSL6s=")

pp "lora raw value: #{lora_enc.to_hexstr}"
puts

phypayload = PHYPayload.from_bytes(lora_enc, appskey, :down)
pp phypayload

puts
pp "raw value: #{phypayload.macpayload.frmpayload.value.to_hexstr}"



